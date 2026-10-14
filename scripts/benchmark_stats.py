"""Count benchmark tasks per family and broken variants per flaw (from meta.yaml files).

Writes results/tables/benchmark_flaw_counts.csv (flaw x family matrix) and prints it.
"""
import csv
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FLAWS = [f"F{i}" for i in range(1, 11)]

metas = [yaml.safe_load(p.read_text()) for p in sorted((ROOT / "benchmark").glob("task_*/meta.yaml"))]
families = sorted({m["family"] for m in metas})
tasks_per_family = Counter(m["family"] for m in metas)
counts = Counter((v["flaw"], m["family"]) for m in metas for v in m["variants"])

rows: list[dict[str, str | int]] = []
for flaw in FLAWS:
    per_family = {f"family_{f}": counts[(flaw, f)] for f in families}
    rows.append({"flaw": flaw, **per_family, "total": sum(per_family.values())})
family_totals = {f"family_{f}": sum(counts[(x, f)] for x in FLAWS) for f in families}
rows.append({"flaw": "total", **family_totals, "total": sum(family_totals.values())})

out = ROOT / "results" / "tables" / "benchmark_flaw_counts.csv"
with open(out, "w", newline="") as fh:
    writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

print("tasks per family:", dict(sorted(tasks_per_family.items())), "| total tasks:", len(metas))
print(f"{'flaw':6}" + "".join(f"fam{f:<3}" for f in families) + "total")
for r in rows:
    print(f"{r['flaw']:6}" + "".join(f"{r[f'family_{f}']:<6}" for f in families) + str(r["total"]))
print(f"Wrote {out.relative_to(ROOT)}")
