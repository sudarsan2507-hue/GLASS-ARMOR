"""Phase 3 evaluation: score every saved model output with the tests, the gate and the baselines.

For each results/raw/<model>/<task>/sample_<i>.json (+ .py):
  - generation status (ok / timeout / error) and whether the output hit the token cap
  - syntax_ok: the file parses as Python
  - uses_oqs: the file imports liboqs (otherwise it was not migrated at all)
  - tests: the task's test_original.py run against the output
  - gate: static tier (our Semgrep rules + dataflow, one batch) and adversarial tier
    (subprocess per file, with a timeout)
  - baselines: default Semgrep (p/python) and Bandit finding counts

Model outputs are untrusted code: tests and adversarial checks run in a subprocess whose
working directory and TEMP are a throwaway folder.

Writes results/tables/phase3_eval.csv and prints a summary.
Usage: python scripts/evaluate.py [--limit N]
"""
import argparse
import ast
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gate.run_gate import StaticError, run_static_batch  # noqa: E402
from scripts.validate_gate import bandit, default_semgrep  # noqa: E402

RAW = ROOT / "results" / "raw"
BENCH = ROOT / "benchmark"
OUT = ROOT / "results" / "tables" / "phase3_eval.csv"
TEST_TIMEOUT = 300
ADV_TIMEOUT = 300
USES_OQS = re.compile(r"^\s*(import\s+oqs\b|from\s+oqs\b)", re.MULTILINE)


def sandbox_env(tmp):
    return dict(os.environ, TEMP=tmp, TMP=tmp, TMPDIR=tmp, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")


def run_tests(task, target):
    """Run the task's tests against target in a throwaway dir. Returns dict."""
    tmp = tempfile.mkdtemp(prefix="pqgate_eval_")
    try:
        shutil.copy(BENCH / task / "test_original.py", tmp)
        env = sandbox_env(tmp)
        env["PQGATE_TARGET"] = str(Path(target).resolve())  # tests run in another cwd
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_original.py"],
                cwd=tmp, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=TEST_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"tests_status": "timeout", "tests_passed": 0, "tests_failed": 0, "tests_errors": 0,
                    "all_tests_pass": False}
        text = proc.stdout.decode("utf-8", errors="replace").strip()
        summary = text.splitlines()[-1] if text else ""
        counts = {k: int(n) for n, k in re.findall(r"(\d+) (passed|failed|errors?)", summary)}
        return {"tests_status": "ran", "tests_passed": counts.get("passed", 0),
                "tests_failed": counts.get("failed", 0),
                "tests_errors": counts.get("error", 0) + counts.get("errors", 0),
                "all_tests_pass": proc.returncode == 0}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_adversarial(task, target):
    tmp = tempfile.mkdtemp(prefix="pqgate_adv_")
    try:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "adversarial_worker.py"), str(Path(target).resolve()), task],
            cwd=tmp, env=sandbox_env(tmp), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=ADV_TIMEOUT)
        text = proc.stdout.decode("utf-8", errors="replace")
        if "@@RESULT@@" not in text:
            return {"load_error": f"worker gave no result (exit {proc.returncode})", "checks": {}}
        return json.loads(text.rsplit("@@RESULT@@", 1)[1])
    except subprocess.TimeoutExpired:
        return {"load_error": "adversarial timeout", "checks": {}}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def in_chunks(fn, paths, size=50):
    """Call a batch tool on at most `size` files at a time (Windows limits command-line length)."""
    merged = {}
    for i in range(0, len(paths), size):
        merged.update(fn(paths[i:i + size]))
    return merged


def collect():
    samples = []
    for log_path in sorted(RAW.glob("*/*/sample_*.json")):
        log = json.loads(log_path.read_text(encoding="utf-8"))
        samples.append({"log": log, "py": log_path.with_suffix(".py")})
    return samples


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="only the first N samples (for a quick check)")
    args = ap.parse_args()

    samples = collect()[: args.limit] if args.limit else collect()
    print(f"{len(samples)} samples found", flush=True)

    for s in samples:
        code = s["py"].read_text(encoding="utf-8") if s["py"].exists() else ""
        s["code"] = code
        try:
            ast.parse(code)
            s["syntax_ok"] = bool(code.strip())
        except SyntaxError:
            s["syntax_ok"] = False

    parsable = [s["py"] for s in samples if s["syntax_ok"]]
    static_error = None
    try:
        static = in_chunks(run_static_batch, parsable)
    except StaticError as e:
        static, static_error = {}, str(e)
        print("STATIC TIER FAILED:", e)
    sg = in_chunks(default_semgrep, parsable)
    bd = in_chunks(bandit, parsable)

    rows = []
    for n, s in enumerate(samples, 1):
        log, path = s["log"], s["py"]
        row = {"model": log["model"], "digest": (log.get("digest") or log.get("api_model_id") or "")[:20], "task": log["task"],
               "sample": log["sample"], "seed": log["seed"], "gen_status": log["status"],
               "done_reason": log.get("done_reason"), "duration_s": log.get("duration_s"),
               "syntax_ok": s["syntax_ok"], "uses_oqs": bool(USES_OQS.search(s["code"]))}
        if s["syntax_ok"]:
            row.update(run_tests(log["task"], path))
            key = str(path.resolve())
            static_flags = sorted(static.get(key, {})) if not static_error else []
            adv = run_adversarial(log["task"], path)
            adv_fail = sorted(c for c, v in adv["checks"].items() if v is False)
            flags = sorted(set(static_flags) | set(adv_fail))
            row.update({
                "gate_verdict": "ERROR" if static_error else ("FAIL" if flags else "PASS"),
                "gate_flags": "|".join(flags),
                "static_flags": "|".join(static_flags),
                "adversarial": json.dumps(adv["checks"]),
                "adv_load_error": adv["load_error"] or "",
                "semgrep_default_findings": sg.get(key, 0),
                "bandit_findings": bd.get(key, 0),
            })
        else:
            row.update({"tests_status": "not run (syntax)", "all_tests_pass": False,
                        "gate_verdict": "", "gate_flags": ""})
        rows.append(row)
        print(f"[{n:3}/{len(samples)}] {row['model']:18} {row['task']:28} s{row['sample']} "
              f"tests={'PASS' if row['all_tests_pass'] else 'fail'} oqs={row['uses_oqs']} "
              f"gate={row.get('gate_verdict', '')} {row.get('gate_flags', '')}", flush=True)

    fields = []
    for r in rows:
        fields += [k for k in r if k not in fields]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    print("\nSummary per model")
    by_model = defaultdict(list)
    for r in rows:
        by_model[r["model"]].append(r)
    for model, rs in by_model.items():
        ok = [r for r in rs if r["gen_status"] == "ok"]
        passing = [r for r in rs if r["all_tests_pass"]]
        migrated_passing = [r for r in passing if r["uses_oqs"]]
        insecure = [r for r in migrated_passing if r["gate_verdict"] == "FAIL"]
        print(f"  {model}: {len(rs)} samples | generated ok {len(ok)} | syntax ok "
              f"{sum(r['syntax_ok'] for r in rs)} | all tests pass {len(passing)} | "
              f"of those use liboqs {len(migrated_passing)} | of those gate FAIL {len(insecure)}")
        flag_counts = Counter(f for r in migrated_passing for f in r["gate_flags"].split("|") if f)
        print(f"    gate checks fired on test-passing PQC migrations: {dict(sorted(flag_counts.items()))}")
    print(f"\nWrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
