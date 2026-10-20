"""Stricter "was it migrated?" test, added after the blind labels showed that `import oqs`
alone over-counts (files that import liboqs but keep RSA/ECDSA for the real work).

really_uses_oqs: some function or method body (not module-level demo code) calls
oqs.KeyEncapsulation / oqs.Signature, or KeyEncapsulation / Signature imported from oqs.

Adds the column to results/tables/phase3_eval.csv as results/tables/phase3_eval_strict.csv,
prints the headline numbers under both definitions, and checks the stricter test against the
blind labeller's "not actually migrated" notes (labeling/labels_ai.csv + results/labeling_key.csv).
Usage: python scripts/strict_migration.py
"""
import ast
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "results" / "tables" / "phase3_eval.csv"
OUT = ROOT / "results" / "tables" / "phase3_eval_strict.csv"
OQS_CLASSES = {"KeyEncapsulation", "Signature"}


def really_uses_oqs(code):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "oqs":
            imported |= {a.asname or a.name for a in node.names if a.name in OQS_CLASSES}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Attribute) and f.attr in OQS_CLASSES and \
                        isinstance(f.value, ast.Name) and f.value.id == "oqs":
                    return True
                if isinstance(f, ast.Name) and f.id in imported:
                    return True
    return False


def code_path(row):
    model_dir = row["model"].replace(":", "_").replace("/", "_")
    return ROOT / "results" / "raw" / model_dir / row["task"] / f"sample_{row['sample']}.py"


def main():
    rows = list(csv.DictReader(open(EVAL, encoding="utf-8")))
    for r in rows:
        r["really_uses_oqs"] = really_uses_oqs(code_path(r).read_text(encoding="utf-8"))
    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    for label, col in (("imports liboqs (Phase 3 definition)", "uses_oqs"),
                       ("calls liboqs in a function (strict)", "really_uses_oqs")):
        pop = [r for r in rows if r["all_tests_pass"] == "True" and str(r[col]) == "True"]
        fail = [r for r in pop if r["gate_verdict"] == "FAIL"]
        print(f"\n{label}: test-passing migrations {len(pop)}, gate FAIL {len(fail)} "
              f"({len(fail) / len(pop):.0%}), distinct tasks flagged {len({(r['model'], r['task']) for r in fail})}")
        for m in sorted({r["model"] for r in rows}):
            mp = [r for r in pop if r["model"] == m]
            print(f"  {m:22} {len(mp):3} migrations, gate FAIL {sum(r['gate_verdict'] == 'FAIL' for r in mp)}")

    # agreement with the blind labeller's "not actually migrated" notes
    key = {r["item"]: r for r in csv.DictReader(open(ROOT / "results" / "labeling_key.csv", encoding="utf-8"))}
    strict = {(r["model"], r["task"], r["sample"]): r["really_uses_oqs"] for r in rows}
    agree = disagree = 0
    for lab in csv.DictReader(open(ROOT / "labeling" / "labels_ai.csv", encoding="utf-8")):
        k = key[lab["item"]]
        labeller_unmigrated = "never actually migrated" in (lab["other_flaw"] + lab["notes"]).lower() or \
            "not migrated" in (lab["other_flaw"] + lab["notes"]).lower() or \
            "unused" in (lab["other_flaw"] + lab["notes"]).lower()
        mine_unmigrated = not strict[(k["model"], k["task"], k["sample"])]
        if labeller_unmigrated == mine_unmigrated:
            agree += 1
        else:
            disagree += 1
            print(f"  disagree {lab['item']}: labeller unmigrated={labeller_unmigrated}, strict test unmigrated={mine_unmigrated}"
                  f" | {lab['other_flaw'][:80]}")
    print(f"\nstrict test vs labeller on 'not actually migrated': agree {agree}/35, disagree {disagree}")
    print(f"Wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
