"""Validate the benchmark: every original, reference and broken variant must pass its task's tests.

For each task it runs test_original.py against original.py, reference_pqc.py and every
file in broken/, prints a table, writes results/tables/benchmark_validation.csv, and exits
with an error if anything fails. It also checks that meta.yaml and broken/ list the same files.

Usage: python scripts/validate_benchmark.py [task_folder ...]
"""
import csv
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"


def run_tests(task_dir, target):
    """Run the task's tests against one file. Returns (passed, failed, errors, ok)."""
    env = dict(os.environ, PQGATE_TARGET=str(target))
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_original.py"],
        cwd=task_dir, env=env, capture_output=True, text=True, timeout=600)
    summary = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    counts = {k: int(n) for n, k in re.findall(r"(\d+) (passed|failed|error)", summary)}
    return counts.get("passed", 0), counts.get("failed", 0), counts.get("error", 0), proc.returncode == 0


def main():
    tasks = sys.argv[1:] or sorted(d.name for d in BENCH.glob("task_*") if d.is_dir())
    rows, problems = [], []
    for task in tasks:
        task_dir = BENCH / task
        meta = yaml.safe_load((task_dir / "meta.yaml").read_text())
        flaw_of = {v["file"]: v["flaw"] for v in meta["variants"]}

        broken_files = sorted(p.name for p in (task_dir / "broken").glob("*.py"))
        if set(broken_files) != set(flaw_of):
            problems.append(f"{task}: meta.yaml variants {sorted(flaw_of)} != broken/ {broken_files}")

        targets = [("original", "-", task_dir / "original.py"),
                   ("reference", "-", task_dir / "reference_pqc.py")]
        targets += [("broken", flaw_of.get(f, "?"), task_dir / "broken" / f) for f in broken_files]
        for kind, flaw, path in targets:
            passed, failed, errors, ok = run_tests(task_dir, path)
            name = path.name if kind != "broken" else f"broken/{path.name}"
            rows.append({"task": task, "kind": kind, "file": name, "flaw": flaw,
                         "passed": passed, "failed": failed, "errors": errors,
                         "all_tests_pass": ok})
            print(f"{task:28} {name:36} {flaw:4} {passed:3} passed {failed:2} failed "
                  f"{errors:2} errors  {'OK' if ok else 'FAIL'}")
            if not ok:
                problems.append(f"{task}/{name}: tests did not all pass")

    out = ROOT / "results" / "tables" / "benchmark_validation.csv"
    with open(out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    broken = [r for r in rows if r["kind"] == "broken"]
    invisible = sum(r["all_tests_pass"] for r in broken)
    print(f"\nTasks: {len(tasks)}  broken variants: {len(broken)}  "
          f"test-invisible: {invisible}/{len(broken)}")
    print(f"Wrote {out.relative_to(ROOT)}")
    if problems:
        print("\nVALIDATION FAILED:")
        for p in problems:
            print("  -", p)
        sys.exit(1)
    print("VALIDATION PASSED")


if __name__ == "__main__":
    main()
