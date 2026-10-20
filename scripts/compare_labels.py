"""Compare the gate's verdicts with the blind hand labels (labeling/labels.csv).

Uses only labelled rows (secure = yes / no). "unsure" rows are counted and reported
separately, never guessed. Ground truth: secure == "no" means the item has a flaw.

Prints and writes results/tables/gate_vs_labels.csv (one row per item) and a summary:
  - confusion matrix (gate FAIL/PASS vs label insecure/secure), precision, recall
  - the same with items grouped by task, because samples of one task are similar
  - per-flaw view: for each flaw a labeller marked, did the gate flag the item?
Usage: python scripts/compare_labels.py [labels file, default labeling/labels.csv]
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABELS = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "labeling" / "labels.csv"
KEY = ROOT / "results" / "labeling_key.csv"
EVAL = ROOT / "results" / "tables" / "phase3_eval.csv"
OUT = ROOT / "results" / "tables" / f"gate_vs_{LABELS.stem}.csv"
FLAWS = [f"F{i}" for i in range(1, 11)]


def ratio(a, b):
    return f"{a}/{b} = {a / b:.0%}" if b else f"{a}/0 (undefined)"


def main():
    labels = list(csv.DictReader(open(LABELS, encoding="utf-8")))
    key = {r["item"]: r for r in csv.DictReader(open(KEY, encoding="utf-8"))}
    gate = {(r["model"], r["task"], r["sample"]): r for r in csv.DictReader(open(EVAL, encoding="utf-8"))}

    rows, unsure, unlabelled = [], [], []
    for lab in labels:
        verdict = lab["secure"].strip().lower()
        if not verdict:
            unlabelled.append(lab["item"])
            continue
        if verdict not in ("yes", "no"):
            unsure.append(lab["item"])
            continue
        k = key[lab["item"]]
        g = gate[(k["model"], k["task"], k["sample"])]
        rows.append({
            "item": lab["item"], "model": k["model"], "task": k["task"], "sample": k["sample"],
            "label_insecure": verdict == "no",
            "label_flaws": "|".join(f for f in FLAWS if lab[f].strip()),
            "gate_fail": g["gate_verdict"] == "FAIL",
            "gate_flags": g["gate_flags"],
        })

    print(f"labels file: {LABELS.name}")
    print(f"labelled: {len(rows)} | unsure: {len(unsure)} {unsure} | not yet labelled: {len(unlabelled)}")
    if not rows:
        return
    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    def report(units, title):
        tp = sum(u["gate_fail"] and u["label_insecure"] for u in units)
        fp = sum(u["gate_fail"] and not u["label_insecure"] for u in units)
        fn = sum(not u["gate_fail"] and u["label_insecure"] for u in units)
        tn = sum(not u["gate_fail"] and not u["label_insecure"] for u in units)
        print(f"\n{title}")
        print(f"  gate FAIL & insecure (TP) {tp} | gate FAIL & secure (FP) {fp} | "
              f"gate PASS & insecure (FN) {fn} | gate PASS & secure (TN) {tn}")
        print(f"  precision {ratio(tp, tp + fp)} | recall {ratio(tp, tp + fn)}")

    report(rows, "Per item")
    by_task = defaultdict(list)
    for r in rows:
        by_task[(r["model"], r["task"])].append(r)
    # a (model, task) group counts as insecure / flagged if any of its labelled items is
    groups = [{"label_insecure": any(x["label_insecure"] for x in g), "gate_fail": any(x["gate_fail"] for x in g)}
              for g in by_task.values()]
    report(groups, f"Per (model, task) group ({len(groups)} groups; samples of one task are similar)")

    print("\nPer flaw marked by the labeller: items with that flaw, and how many the gate failed")
    for f in FLAWS:
        items = [r for r in rows if f in r["label_flaws"].split("|")]
        if items:
            print(f"  {f}: {ratio(sum(r['gate_fail'] for r in items), len(items))}")
    missed = [r for r in rows if r["label_insecure"] and not r["gate_fail"]]
    false_alarms = [r for r in rows if r["gate_fail"] and not r["label_insecure"]]
    print("\nGate missed (labelled insecure, gate PASS):", [f"{r['item']} {r['task']} {r['label_flaws']}" for r in missed])
    print("Gate false alarms (labelled secure, gate FAIL):", [f"{r['item']} {r['task']} {r['gate_flags']}" for r in false_alarms])
    print(f"\nWrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
