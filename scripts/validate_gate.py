"""Gate validation + baselines on the benchmark.

Runs on all 20 reference_pqc.py files (correct code) and all broken variants:
  - PQ-GATE (our Semgrep rules P1-P6 + adversarial checks A1-A6)
  - baseline "tests only": from results/tables/benchmark_validation.csv
  - baseline "default Semgrep": the public p/python ruleset
  - baseline "Bandit": any Bandit finding

A variant is "caught (expected)" if the gate raises one of the checks listed for it in
meta.yaml, and "flagged" if the gate raises any check at all. A reference that is
flagged is a false positive.

Writes:
  results/tables/gate_validation.csv   one row per file
  results/tables/gate_by_flaw.csv      detection per flaw, gate vs baselines
  results/tables/gate_by_check.csv     TP / FN / FP per gate check
"""
import csv
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gate.run_gate import SEMGREP_EXE, run_gate, run_static_batch  # noqa: E402

BENCH = ROOT / "benchmark"
TABLES = ROOT / "results" / "tables"
BANDIT_EXE = ROOT / ".venv" / "Scripts" / "bandit.exe"
CHECKS = ["P1", "P2", "P3", "P4", "P5", "P6", "A1", "A2", "A3", "A4", "A5", "A6"]
FLAWS = [f"F{i}" for i in range(1, 11)]


def collect_files():
    files = []
    for task_dir in sorted(BENCH.glob("task_*")):
        meta = yaml.safe_load((task_dir / "meta.yaml").read_text())
        files.append({"task": task_dir.name, "kind": "reference", "path": task_dir / "reference_pqc.py",
                      "flaw": "", "expected": []})
        for v in meta["variants"]:
            files.append({"task": task_dir.name, "kind": "variant", "path": task_dir / "broken" / v["file"],
                          "flaw": v["flaw"], "expected": v.get("expected_checks", [])})
    return files


def default_semgrep(paths):
    """Number of p/python findings per file."""
    cmd = [SEMGREP_EXE, "--config", "p/python", "--metrics", "off", "--no-git-ignore",
           "--quiet", "--json"] + [str(p) for p in paths]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900)
    data = json.loads(proc.stdout.decode("utf-8-sig", errors="replace"))
    if data.get("errors"):
        raise RuntimeError(f"default semgrep errors: {str(data['errors'])[:300]}")
    counts = defaultdict(int)
    for r in data["results"]:
        counts[str(Path(r["path"]).resolve())] += 1
    return counts


def bandit(paths):
    """Number of Bandit findings per file (any severity / confidence)."""
    cmd = [str(BANDIT_EXE), "-f", "json", "-q"] + [str(p) for p in paths]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
    data = json.loads(proc.stdout.decode("utf-8-sig", errors="replace"))
    if data.get("errors"):
        raise RuntimeError(f"bandit errors: {str(data['errors'])[:300]}")
    counts = defaultdict(int)
    for r in data["results"]:
        counts[str(Path(r["filename"]).resolve())] += 1
    return counts


def tests_only():
    """True if the file fails at least one functional test (= tests 'catch' it)."""
    caught = {}
    with open(TABLES / "benchmark_validation.csv", newline="") as fh:
        for row in csv.DictReader(fh):
            sub = "" if row["kind"] in ("original", "reference") else "broken"
            path = (BENCH / row["task"] / sub / row["file"]).resolve()
            caught[str(path)] = row["all_tests_pass"] != "True"
    return caught


def main():
    files = collect_files()
    paths = [f["path"] for f in files]
    print(f"{len(files)} files ({sum(f['kind'] == 'reference' for f in files)} references)")

    print("running PQ-GATE static rules (one Semgrep batch) ...", flush=True)
    static = run_static_batch(paths)
    print("running default Semgrep (p/python) ...", flush=True)
    sg_default = default_semgrep(paths)
    print("running Bandit ...", flush=True)
    bandit_counts = bandit(paths)
    tests = tests_only()

    rows = []
    print("running adversarial checks ...", flush=True)
    for i, f in enumerate(files, 1):
        key = str(f["path"].resolve())
        result = run_gate(f["path"], f["task"], static=static[key])
        flags = result["flags"]
        rows.append({
            "task": f["task"], "kind": f["kind"], "file": f["path"].name, "flaw": f["flaw"],
            "expected_checks": "|".join(f["expected"]),
            "gate_verdict": result["verdict"],
            "gate_flags": "|".join(flags),
            "caught_expected": bool(set(f["expected"]) & set(flags)) if f["kind"] == "variant" else "",
            "adversarial": json.dumps({k: v for k, v in result["adversarial"].items()}),
            "tests_fail": tests.get(key, ""),
            "semgrep_default_findings": sg_default.get(key, 0),
            "bandit_findings": bandit_counts.get(key, 0),
        })
        print(f"  [{i:2}/{len(files)}] {f['task']}/{f['path'].name}: {result['verdict']} {flags}", flush=True)

    TABLES.mkdir(parents=True, exist_ok=True)
    with open(TABLES / "gate_validation.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    refs = [r for r in rows if r["kind"] == "reference"]
    variants = [r for r in rows if r["kind"] == "variant"]

    def flagged(r, tool):
        return {"gate": r["gate_verdict"] != "PASS",
                "gate_expected": r["caught_expected"] is True,
                "tests": r["tests_fail"] is True,
                "semgrep": r["semgrep_default_findings"] > 0,
                "bandit": r["bandit_findings"] > 0}[tool]

    tools = ["tests", "semgrep", "bandit", "gate", "gate_expected"]

    # -- per flaw --
    by_flaw = []
    for flaw in FLAWS + ["all"]:
        vs = variants if flaw == "all" else [r for r in variants if r["flaw"] == flaw]
        row = {"flaw": flaw, "variants": len(vs)}
        for t in tools:
            row[t] = sum(flagged(r, t) for r in vs)
        by_flaw.append(row)
    fp_row = {"flaw": "FP on 20 references", "variants": len(refs)}
    for t in tools:
        fp_row[t] = "" if t == "gate_expected" else sum(flagged(r, t) for r in refs)
    by_flaw.append(fp_row)
    with open(TABLES / "gate_by_flaw.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(by_flaw[0]))
        w.writeheader()
        w.writerows(by_flaw)

    # -- per check --
    stats = {c: {"check": c, "TP": 0, "FN": 0, "fired_unexpected_on_variant": 0, "FP_on_reference": 0}
             for c in CHECKS}
    for r in variants:
        exp, fl = set(r["expected_checks"].split("|")) - {""}, set(r["gate_flags"].split("|")) - {""}
        for c in CHECKS:
            if c in exp:
                stats[c]["TP" if c in fl else "FN"] += 1
            elif c in fl:
                stats[c]["fired_unexpected_on_variant"] += 1
    for r in refs:
        for c in set(r["gate_flags"].split("|")) - {""}:
            if c in stats:
                stats[c]["FP_on_reference"] += 1
    with open(TABLES / "gate_by_check.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(stats["P1"]))
        w.writeheader()
        w.writerows(stats.values())

    # -- print summary --
    print("\nDetection per flaw (variants flagged; last row = false positives on references)")
    print(f"{'flaw':22}{'n':>4}" + "".join(f"{t:>15}" for t in tools))
    for row in by_flaw:
        print(f"{row['flaw']:22}{row['variants']:>4}" + "".join(f"{row[t]!s:>15}" for t in tools))
    print("\nPer gate check: TP / FN / fired-on-other-variant / FP-on-reference")
    for s in stats.values():
        print(f"  {s['check']}: {s['TP']:>3} {s['FN']:>3} {s['fired_unexpected_on_variant']:>3} {s['FP_on_reference']:>3}")
    missed = [r for r in variants if r["caught_expected"] is not True]
    fps = [r for r in refs if r["gate_verdict"] != "PASS"]
    print(f"\nVariants not caught by an expected check: {len(missed)}")
    for r in missed:
        print(f"  {r['task']}/{r['file']} expected={r['expected_checks']} got={r['gate_flags'] or '-'}")
    print(f"References flagged (false positives): {len(fps)}")
    for r in fps:
        print(f"  {r['task']}/reference_pqc.py got={r['gate_flags']} verdict={r['gate_verdict']}")
    print(f"\nWrote {', '.join(n for n in ('gate_validation.csv', 'gate_by_flaw.csv', 'gate_by_check.csv'))}")


if __name__ == "__main__":
    main()
