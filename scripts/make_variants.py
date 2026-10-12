"""Build broken variants from each task's reference_pqc.py using exact text replacements.

Each variant = reference + a small set of edits that introduce ONE flaw. Keeping the edits
here makes every variant an auditable, minimal diff. Variant specs live in
benchmark/<task>/variants.py as a VARIANTS dict:
    {"b1_F1_raw_secret_key": [(old_text, new_text), ...], ...}
Every old_text must occur in the file, otherwise the script stops (no silent no-ops).

Usage: python scripts/make_variants.py [task_folder ...]
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"


def build_task(task_dir):
    spec_file = task_dir / "variants.py"
    spec = importlib.util.spec_from_file_location("variants", spec_file)
    variants = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(variants)

    reference = (task_dir / "reference_pqc.py").read_text(encoding="utf-8")
    out_dir = task_dir / "broken"
    out_dir.mkdir(exist_ok=True)
    for name, edits in variants.VARIANTS.items():
        code = reference
        for old, new in edits:
            if old not in code:
                raise SystemExit(f"{task_dir.name}/{name}: text not found:\n{old}")
            code = code.replace(old, new)
        (out_dir / f"{name}.py").write_text(code, encoding="utf-8")
        print(f"  wrote {task_dir.name}/broken/{name}.py ({len(edits)} edits)")


tasks = sys.argv[1:] or sorted(d.name for d in BENCH.glob("task_*") if (d / "variants.py").exists())
for t in tasks:
    build_task(BENCH / t)
