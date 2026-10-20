"""Phase 4: repair loop. Does gate feedback fix test-passing insecure migrations where test
feedback does not?

Items: Phase 3 outputs that pass all tests, use liboqs and FAIL the gate
(results/tables/phase3_eval.csv). Each is repaired by the model that wrote it, in two
conditions:
  tests : feedback = test-suite results only
  gate  : feedback = test-suite results + the gate's findings
Each round: prompt (repair text + API card + current file) -> model -> new file -> tests +
gate. At least 1 round, at most repair.max_rounds; stop early once the condition's own
signal is clean (tests: all tests pass; gate: all tests pass and gate PASS), or when the
model returns the file unchanged (the next prompt would be identical).

Every round is saved: results/repair/<condition>/<model>/<task>/sample_<i>/round_<k>.py/.json
(round_0 = the Phase 3 output, re-evaluated). Resumable: existing rounds are skipped; a
Groq rate limit stops the run without writing anything (re-run the same command).

Usage:
    python harness/repair.py                                  # all items, both conditions
    python harness/repair.py --models qwen2.5-coder:7b --conditions gate
"""
import argparse
import ast
import csv
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gate.run_gate import StaticError, run_static_batch  # noqa: E402
from harness.migrate import (CONFIG, StopRun, call_groq, call_ollama, extract_code,  # noqa: E402
                             groq_key, model_dir_name)
from scripts.evaluate import USES_OQS, run_adversarial, sandbox_env  # noqa: E402

EVAL = ROOT / "results" / "tables" / "phase3_eval.csv"
OUT = ROOT / "results" / "repair"
CONDITIONS = ("tests", "gate")

# Plain-language text for adversarial findings (static findings carry their own messages)
ADV_TEXT = {
    "A1": "With liboqs unavailable or failing, the code still works by falling back to classical cryptography.",
    "A2": "When a classical algorithm is offered (alone or next to the post-quantum one), it is accepted or preferred.",
    "A3": "On wrong keys or tampered input, secret key material appears in an exception, log or output, "
          "or tampered data is accepted.",
    "A4": "In the hybrid key exchange, corrupting only the ML-KEM secret still gives both sides the same key.",
    "A5": "A signature still verifies after the context, a signed field or part of the message is changed.",
    "A6": "The same AES-GCM key and nonce pair is used more than once.",
}


def run_tests_verbose(task, target):
    """Run the task's tests; return (all_pass, passed, failed, failure_lines)."""
    tmp = tempfile.mkdtemp(prefix="pqgate_rep_")
    try:
        shutil.copy(ROOT / "benchmark" / task / "test_original.py", tmp)
        env = sandbox_env(tmp)
        env["PQGATE_TARGET"] = str(Path(target).resolve())
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-rfE", "--tb=line", "-p", "no:cacheprovider",
                 "test_original.py"], cwd=tmp, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=300)
        except subprocess.TimeoutExpired:
            return False, 0, 0, ["the test run timed out after 300 s"]
        text = proc.stdout.decode("utf-8", errors="replace")
        summary = text.strip().splitlines()[-1] if text.strip() else ""
        counts = {k: int(n) for n, k in re.findall(r"(\d+) (passed|failed|errors?)", summary)}
        failed = counts.get("failed", 0) + counts.get("error", 0) + counts.get("errors", 0)
        lines = [ln.strip() for ln in text.splitlines() if ln.startswith(("FAILED", "ERROR"))][:10]
        if proc.returncode != 0 and not lines:
            lines = [ln for ln in text.strip().splitlines()[-5:]]
        return proc.returncode == 0, counts.get("passed", 0), failed, lines
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def evaluate(task, path):
    """Tests + gate on one file. Returns a dict with results and feedback text."""
    code = path.read_text(encoding="utf-8")
    all_pass, passed, failed, fail_lines = run_tests_verbose(task, path)
    try:
        ast.parse(code)
    except SyntaxError as e:
        fb = f"Test suite: the file is not valid Python ({e.msg}, line {e.lineno})."
        return {"all_tests_pass": False, "tests_passed": passed, "tests_failed": failed,
                "uses_oqs": bool(USES_OQS.search(code)), "gate_verdict": "NOT VALID PYTHON",
                "gate_flags": [], "adv_load_error": None, "feedback_tests": fb, "feedback_gate": fb}
    try:
        static = run_static_batch([path])[str(path.resolve())]
    except StaticError as e:  # record, never crash the run
        return {"all_tests_pass": all_pass, "tests_passed": passed, "tests_failed": failed,
                "uses_oqs": bool(USES_OQS.search(code)), "gate_verdict": "ERROR", "gate_flags": [],
                "adv_load_error": f"static tier failed: {str(e)[:200]}",
                "feedback_tests": "Test suite: could not be fully evaluated.",
                "feedback_gate": "Test suite and security checker: could not be fully evaluated."}
    adv = run_adversarial(task, path)
    adv_fail = sorted(c for c, v in adv["checks"].items() if v is False)
    flags = sorted(set(static) | set(adv_fail))
    if all_pass:
        test_fb = f"Test suite: all {passed} tests passed."
    else:
        test_fb = f"Test suite: {passed} passed, {failed} failed.\n" + "\n".join(fail_lines)
    gate_lines = [f"- [{check}] line {f['line']}: {f['message']}"
                  for check, items in sorted(static.items()) for f in items]
    gate_lines += [f"- [{c}] {ADV_TEXT[c]}" for c in adv_fail]
    gate_fb = ("Security checker: " + ("no problems found." if not flags else
               f"{len(gate_lines)} finding(s):\n" + "\n".join(gate_lines)))
    return {"all_tests_pass": all_pass, "tests_passed": passed, "tests_failed": failed,
            "uses_oqs": bool(USES_OQS.search(code)), "gate_verdict": "FAIL" if flags else "PASS",
            "gate_flags": flags, "adv_load_error": adv["load_error"],
            "feedback_tests": test_fb, "feedback_gate": test_fb + "\n\n" + gate_fb}


def clean(condition, ev):
    return ev["all_tests_pass"] and (condition == "tests" or ev["gate_verdict"] == "PASS")


def items_to_repair():
    rows = list(csv.DictReader(open(EVAL, encoding="utf-8")))
    return [r for r in rows if r["all_tests_pass"] == "True" and r["uses_oqs"] == "True"
            and r["gate_verdict"] == "FAIL"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*")
    ap.add_argument("--conditions", nargs="*", default=list(CONDITIONS))
    args = ap.parse_args()

    entries = {m["name"]: m for m in CONFIG["models"]}
    rep = CONFIG["repair"]
    card = CONFIG["prompts"]["api_card"]
    items = [r for r in items_to_repair() if not args.models or r["model"] in args.models]
    key = groq_key() if any(entries[r["model"]].get("provider") == "groq" for r in items) else None
    print(f"{len(items)} items x {len(args.conditions)} conditions, max {rep['max_rounds']} rounds", flush=True)

    for cond in args.conditions:
        for it in items:
            model, task, sample = it["model"], it["task"], int(it["sample"])
            entry, seed = entries[model], int(it["seed"])
            d = OUT / cond / model_dir_name(model) / task / f"sample_{sample}"
            d.mkdir(parents=True, exist_ok=True)
            r0 = d / "round_0.json"
            if not r0.exists():
                src = ROOT / "results" / "raw" / model_dir_name(model) / task / f"sample_{sample}.py"
                shutil.copy(src, d / "round_0.py")
                r0.write_text(json.dumps({"round": 0, "source": str(src.relative_to(ROOT)),
                                          "eval": evaluate(task, d / "round_0.py")}, indent=2), encoding="utf-8")
            for k in range(1, rep["max_rounds"] + 1):
                prev = json.loads((d / f"round_{k - 1}.json").read_text(encoding="utf-8"))
                if k > 1 and clean(cond, prev["eval"]):
                    break
                if (d / f"round_{k}.json").exists():
                    continue
                if k > 1 and (prev.get("status") != "ok" or prev.get("unchanged")):
                    break  # error, or the model returned the file unchanged: the next prompt would be identical
                code = (d / f"round_{k - 1}.py").read_text(encoding="utf-8")
                feedback = prev["eval"][f"feedback_{cond}"]
                prompt = (rep[f"prompt_{cond}"].format(feedback=feedback)
                          + f"\n\n{card}\n```python\n{code}\n```\n")
                print(f"[{cond}] {model} {task} s{sample} round {k}", flush=True)
                start = time.time()
                try:
                    if entry.get("provider") == "groq":
                        status, resp, error = call_groq(entry, prompt, seed, key)
                        raw = ((resp or {}).get("choices", [{}])[0].get("message") or {}).get("content") or ""
                    else:
                        status, resp, error = call_ollama(model, prompt, seed)
                        raw = resp["response"] if resp else ""
                except StopRun as e:
                    print(f"    STOPPED, nothing written: {e}. Re-run the same command later.", flush=True)
                    return
                new_code = extract_code(raw) if raw else ""
                (d / f"round_{k}.py").write_text(new_code, encoding="utf-8")
                log = {"round": k, "condition": cond, "model": model, "task": task, "sample": sample,
                       "seed": seed, "prompt": prompt, "status": status, "error": error,
                       "raw_response": raw, "unchanged": new_code.strip() == code.strip(),
                       "duration_s": round(time.time() - start, 1),
                       "timestamp": datetime.now(timezone.utc).isoformat()}
                if status == "ok" and new_code.strip():
                    log["eval"] = evaluate(task, d / f"round_{k}.py")
                else:
                    log["eval"] = prev["eval"] | {"all_tests_pass": False, "gate_verdict": "NO OUTPUT"}
                (d / f"round_{k}.json").write_text(json.dumps(log, indent=2), encoding="utf-8")
                e = log["eval"]
                print(f"    {status} | tests {'pass' if e['all_tests_pass'] else 'FAIL'} | "
                      f"gate {e['gate_verdict']} {e.get('gate_flags', '')} | unchanged={log['unchanged']}", flush=True)
                if status != "ok":
                    break
    print("Finished.", flush=True)


if __name__ == "__main__":
    main()
