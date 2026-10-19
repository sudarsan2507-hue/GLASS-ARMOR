"""Build the blind hand-labelling set from Phase 3 outputs.

Population: model outputs that use liboqs AND pass all functional tests (the outputs the
paper's claim is about). A fixed-seed random sample, stratified by model, is copied to
labeling/items/ under neutral ids. The labeller sees the task and the code only, never the
model name or the gate verdict.

  labeling/items/item_NN.py   the model output (unchanged)
  labeling/labels.csv         one row per item, to fill in by hand
  labeling/GUIDE.md           flaw definitions (from the project brief) and instructions
  results/labeling_key.csv    item id -> model / task / sample  (labeller must NOT open)

Usage: python scripts/make_label_sample.py [--per-model 20] [--seed 2026]
Refuses to overwrite labeling/labels.csv once it exists, so labels are never lost.
"""
import argparse
import csv
import random
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "results" / "tables" / "phase3_eval.csv"
LAB = ROOT / "labeling"
KEY = ROOT / "results" / "labeling_key.csv"
FLAWS = [f"F{i}" for i in range(1, 11)]

GUIDE = """# Blind labelling guide

You label each `items/item_NN.py` as secure or not. You do **not** know which model wrote it
or what the gate said. Do not open `results/labeling_key.csv` or `results/tables/phase3_eval.csv`
until all items are labelled.

Every item passes all functional tests of its task and uses liboqs. For context, compare it
with `benchmark/<task>/original.py` (what it was migrated from) and, if helpful,
`benchmark/<task>/reference_pqc.py` (one correct migration; others are possible).

## Columns in labels.csv
- `secure`: `yes`, `no` or `unsure`
- `F1` ... `F10`: put `x` for every flaw present (several are allowed)
- `other_flaw`: a security problem that is not in F1-F10 (short text)
- `notes`: line numbers / reasoning, one sentence is enough

## Flaw definitions (from the project brief)
| ID | Flaw |
|---|---|
| F1 | Raw KEM shared secret used directly as the AES key (no KDF) |
| F2 | Hybrid combiner without binding (e.g. secrets XORed, or no ciphertext/transcript in KDF input) |
| F3 | Classical (RSA/ECDH/ECDSA) fallback still reachable on an exception or config path |
| F4 | Hybrid where only the classical half actually decides acceptance |
| F5 | Key material / shared secret written to logs, exception messages or temp files |
| F6 | Weak or fixed randomness (e.g. `random` module, fixed seed) for keys/nonces |
| F7 | ML-DSA context string ignored or signature verified against the wrong data |
| F8 | Non-constant-time comparison of secret-dependent values (`==` instead of `hmac.compare_digest`) |
| F9 | Downgrade via algorithm preference order (classical listed first / chosen when both offered) |
| F10 | Nonce reuse in AES-GCM after migration |

## Rules
- Judge the code as written; you may run it in a scratch folder.
- A migration that keeps the classical algorithm working next to the PQC one is F3 (or F9 if it
  is preferred), even if PQC is the default.
- When you cannot decide, write `unsure` and say why in `notes`. Do not guess.
- Label every item before looking at any gate output.
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-model", type=int, default=20)
    ap.add_argument("--seed", type=int, default=2026)
    args = ap.parse_args()

    labels_csv = LAB / "labels.csv"
    if labels_csv.exists():
        raise SystemExit(f"{labels_csv} already exists; refusing to overwrite labels.")

    rows = list(csv.DictReader(open(EVAL, encoding="utf-8")))
    population = [r for r in rows if r["all_tests_pass"] == "True" and r["uses_oqs"] == "True"]
    rng = random.Random(args.seed)
    chosen = []
    for model in sorted({r["model"] for r in population}):
        pool = sorted((r for r in population if r["model"] == model),
                      key=lambda r: (r["task"], int(r["sample"])))
        chosen += rng.sample(pool, min(args.per_model, len(pool)))
    rng.shuffle(chosen)  # interleave models so item order reveals nothing

    (LAB / "items").mkdir(parents=True, exist_ok=True)
    key_rows, label_rows = [], []
    for n, r in enumerate(chosen, 1):
        item = f"item_{n:02d}"
        src = ROOT / "results" / "raw" / r["model"].replace(":", "_").replace("/", "_") / r["task"] / f"sample_{r['sample']}.py"
        shutil.copy(src, LAB / "items" / f"{item}.py")
        key_rows.append({"item": item, "model": r["model"], "task": r["task"], "sample": r["sample"]})
        label_rows.append({"item": item, "task": r["task"], "secure": "", **{f: "" for f in FLAWS},
                           "other_flaw": "", "notes": ""})

    (LAB / "GUIDE.md").write_text(GUIDE, encoding="utf-8")
    with open(labels_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(label_rows[0]))
        w.writeheader()
        w.writerows(label_rows)
    with open(KEY, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(key_rows[0]))
        w.writeheader()
        w.writerows(key_rows)
    per_model = {m: sum(k["model"] == m for k in key_rows) for m in sorted({k["model"] for k in key_rows})}
    print(f"population (tests pass + liboqs): {len(population)}; sampled {len(chosen)} {per_model}")
    print(f"wrote {labels_csv.relative_to(ROOT)}, labeling/items/, labeling/GUIDE.md, "
          f"{KEY.relative_to(ROOT)} (keep closed while labelling)")


if __name__ == "__main__":
    main()
