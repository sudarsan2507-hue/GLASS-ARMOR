"""Summarise Phase 4 (results/repair/): did each condition fix the test-passing insecure items?

Per item and condition, the final state is the last round written. An item counts as
"fixed" if its final file passes all tests AND the gate passes. Also reported:
  - "broke tests": final file no longer passes the tests
  - "unchanged": the model never changed the file
  - per gate check: how often a check that fired at round 0 is gone at the end
Writes results/tables/repair_items.csv and results/tables/repair_summary.csv, and lists the
gate-condition fixes for the manual audit (a fix may just evade a name-based check).
Usage: python scripts/summarize_repair.py
"""
import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPAIR = ROOT / "results" / "repair"
TABLES = ROOT / "results" / "tables"


def load_items():
    items = []
    for d in sorted(REPAIR.glob("*/*/*/sample_*")):
        rounds = sorted(d.glob("round_*.json"), key=lambda p: int(p.stem.split("_")[1]))
        if len(rounds) < 2:
            continue  # not repaired yet
        r0 = json.loads(rounds[0].read_text(encoding="utf-8"))
        last = json.loads(rounds[-1].read_text(encoding="utf-8"))
        logs = [json.loads(p.read_text(encoding="utf-8")) for p in rounds[1:]]
        cond, model, task = d.parts[-4], d.parts[-3], d.parts[-2]
        e0, ef = r0["eval"], last["eval"]
        items.append({
            "condition": cond, "model": model, "task": task, "sample": d.name.split("_")[1],
            "rounds": len(rounds) - 1,
            "start_flags": "|".join(e0["gate_flags"]),
            "final_tests_pass": ef["all_tests_pass"],
            "final_gate": ef["gate_verdict"],
            "final_flags": "|".join(ef.get("gate_flags") or []),
            "fixed": ef["all_tests_pass"] and ef["gate_verdict"] == "PASS",
            "broke_tests": not ef["all_tests_pass"],
            "never_changed": all(l.get("unchanged") for l in logs),
            "final_file": str(rounds[-1].with_suffix(".py").relative_to(ROOT)),
        })
    return items


def main():
    items = load_items()
    if not items:
        print("no repaired items yet")
        return
    TABLES.mkdir(parents=True, exist_ok=True)
    with open(TABLES / "repair_items.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(items[0]))
        w.writeheader()
        w.writerows(items)

    groups = defaultdict(list)
    for it in items:
        groups[(it["condition"], it["model"])].append(it)
        groups[(it["condition"], "ALL")].append(it)
    summary = []
    for (cond, model), its in sorted(groups.items()):
        n = len(its)
        summary.append({"condition": cond, "model": model, "items": n,
                        "fixed": sum(i["fixed"] for i in its),
                        "broke_tests": sum(i["broke_tests"] for i in its),
                        "never_changed": sum(i["never_changed"] for i in its),
                        "mean_rounds": round(sum(i["rounds"] for i in its) / n, 2)})
    with open(TABLES / "repair_summary.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary[0]))
        w.writeheader()
        w.writerows(summary)

    print(f"{'condition':9} {'model':22} {'items':>5} {'fixed':>6} {'broke tests':>12} {'never changed':>14} {'rounds':>7}")
    for s in summary:
        print(f"{s['condition']:9} {s['model']:22} {s['items']:>5} {s['fixed']:>6} {s['broke_tests']:>12} "
              f"{s['never_changed']:>14} {s['mean_rounds']:>7}")

    print("\nPer gate check: fired at start -> gone at the end (by condition)")
    for cond in sorted({i["condition"] for i in items}):
        gone, total = defaultdict(int), defaultdict(int)
        for i in (x for x in items if x["condition"] == cond and x["final_tests_pass"]):
            final = set(i["final_flags"].split("|")) - {""}
            for c in set(i["start_flags"].split("|")) - {""}:
                total[c] += 1
                gone[c] += c not in final
        print(f"  {cond}: " + ", ".join(f"{c} {gone[c]}/{total[c]}" for c in sorted(total)))

    audit = [i for i in items if i["condition"] == "gate" and i["fixed"]]
    print(f"\nGate-condition fixes to audit by hand ({len(audit)}): compare round_0.py with the final file")
    for i in audit:
        print(f"  {i['model']} {i['task']} s{i['sample']} (start {i['start_flags']}) -> {i['final_file']}")


if __name__ == "__main__":
    main()
