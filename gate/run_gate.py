"""PQ-GATE security gate — run on a single migrated Python file.

Usage:
    python gate/run_gate.py <target.py> [--task <task_name>] [--json]

Outputs a JSON verdict:
    {
      "target": "path/to/file.py",
      "task": "task_01_file_key_wrap",
      "static": {                    # Semgrep findings, grouped by check id
          "P1": [{"rule": ..., "line": ..., "message": ...}, ...],
          ...
      },
      "adversarial": {               # behavioral check results
          "A1": true,   # true = PASS, false = FAIL, null = N/A
          ...
      },
      "verdict": "PASS" | "FAIL",
      "flags": ["P1", "A3", ...]     # checks that fired
    }

Without --json prints a human-readable summary.
"""
import argparse
import contextlib
import importlib.util
import shutil
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gate import static_dataflow
from gate.adversarial import run_all as run_adversarial

SEMGREP_RULES = ROOT / "gate" / "semgrep_rules"

# Prefer .venv/Scripts/semgrep.exe over system semgrep
_VENV_SEMGREP = ROOT / ".venv" / "Scripts" / "semgrep.exe"
SEMGREP_EXE = str(_VENV_SEMGREP) if _VENV_SEMGREP.exists() else "semgrep"

def _rule_short(full_id):
    """Extract the short rule id from a dotted Semgrep id."""
    return full_id.split(".")[-1]


class StaticError(RuntimeError):
    pass


def run_static_batch(target_paths, config=SEMGREP_RULES):
    """Static tier for many files: our Semgrep rules (one Semgrep run) + the AST dataflow
    checks. Returns {resolved path: {check: [findings]}}.
    Raises StaticError if Semgrep fails, so a crash is never mistaken for 'no findings'."""
    paths = [Path(p).resolve() for p in target_paths]
    cmd = [SEMGREP_EXE, "--config", str(config), "--no-git-ignore", "--quiet",
           "--json", "--metrics", "off"] + [str(p) for p in paths]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        data = json.loads(proc.stdout.decode("utf-8-sig", errors="replace"))
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        raise StaticError(f"semgrep failed: {type(e).__name__}: {e}") from e
    if data.get("errors"):
        raise StaticError(f"semgrep reported errors: {str(data['errors'])[:300]}")

    out = {str(p): {} for p in paths}
    for r in data.get("results", []):
        short = _rule_short(r["check_id"])
        check = r["extra"].get("metadata", {}).get("check", short)
        findings = out.setdefault(str(Path(r["path"]).resolve()), {}).setdefault(check, [])
        item = {"rule": short, "line": r["start"]["line"],
                "message": r["extra"]["message"].split("\n")[0][:120]}
        if item not in findings:
            findings.append(item)

    for p in paths:
        try:
            flow = static_dataflow.check(p.read_text(encoding="utf-8"))
        except SyntaxError as e:
            flow = {"SYNTAX": [{"rule": "python-syntax", "line": e.lineno or 0, "message": str(e)}]}
        for check, items in flow.items():
            out[str(p)].setdefault(check, []).extend(items)
    return out


def run_static(target_path):
    """Run Semgrep rules on one file. Returns {check: [findings]}."""
    return run_static_batch([target_path])[str(Path(target_path).resolve())]


@contextlib.contextmanager
def throwaway_temp():
    """Point TEMP/TMP/TMPDIR (and tempfile) at a fresh dir, delete it afterwards.
    Some targets write key files to the temp dir; they must not land in the real one."""
    tmp_dir = tempfile.mkdtemp(prefix="pqgate_run_")
    saved_env = {k: os.environ.get(k) for k in ("TEMP", "TMP", "TMPDIR")}
    saved_tempdir = tempfile.tempdir
    for k in saved_env:
        os.environ[k] = tmp_dir
    tempfile.tempdir = tmp_dir
    try:
        yield tmp_dir
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        tempfile.tempdir = saved_tempdir
        shutil.rmtree(tmp_dir, ignore_errors=True)


def load_module(target_path, task):
    """Load the target Python file as a fresh module."""
    spec = importlib.util.spec_from_file_location(f"target_{task}", str(target_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_gate(target_path, task, static=None):
    """Run the full gate on a single file. Returns the verdict dict.
    `static` may be passed in from run_static_batch to avoid one Semgrep start per file."""
    target_path = Path(target_path)

    # Tier 1: static
    static_error = None
    if static is None:
        try:
            static = run_static(target_path)
        except StaticError as e:
            static, static_error = None, str(e)

    # Tier 2: adversarial (import and run inside a throwaway temp dir)
    try:
        with throwaway_temp():
            mod = load_module(target_path, task)
            adversarial = run_adversarial(mod, task)
    except Exception as e:
        adversarial = {k: None for k in ("A1", "A2", "A3", "A4", "A5", "A6")}
        adversarial["_load_error"] = str(e)

    # Aggregate flags
    flags = list(static.keys()) if static is not None else []
    for check, result in adversarial.items():
        if check.startswith("_"):
            continue
        if result is False:
            flags.append(check)

    flags = sorted(set(flags))
    if static_error:
        verdict = "ERROR"  # static tier did not run: never report PASS
    else:
        verdict = "FAIL" if flags else "PASS"

    return {
        "target": str(target_path),
        "task": task,
        "static": static,
        "static_error": static_error,
        "adversarial": adversarial,
        "verdict": verdict,
        "flags": flags,
    }


def _infer_task(target_path):
    """Try to infer task name from file path."""
    p = Path(target_path).resolve()
    for part in p.parts:
        if part.startswith("task_"):
            return part
    return "unknown"


def main():
    parser = argparse.ArgumentParser(description="PQ-GATE security gate")
    parser.add_argument("target", help="Python file to check")
    parser.add_argument("--task", default=None,
                        help="Task name (e.g. task_01_file_key_wrap); inferred from path if omitted")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    task = args.task or _infer_task(args.target)
    result = run_gate(args.target, task)

    if args.json:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    # Human-readable summary
    print(f"Target : {result['target']}")
    print(f"Task   : {result['task']}")
    print(f"Verdict: {result['verdict']}")
    if result["flags"]:
        print(f"Flags  : {', '.join(result['flags'])}")
    if result["static"]:
        print("\nStatic findings:")
        for check, findings in sorted(result["static"].items()):
            for f in findings:
                print(f"  [{check}] line {f['line']}: {f['message']}")
    adv = {k: v for k, v in result["adversarial"].items() if not k.startswith("_")}
    if any(v is not None for v in adv.values()):
        print("\nAdversarial checks:")
        for check, val in sorted(adv.items()):
            status = "PASS" if val is True else ("FAIL" if val is False else "N/A")
            print(f"  [{check}] {status}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
