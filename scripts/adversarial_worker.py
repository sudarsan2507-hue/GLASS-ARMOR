"""Run the gate's adversarial checks (A1-A6) on one file and print JSON.

Called by evaluate.py in a subprocess (with a timeout), so a model output that hangs or
crashes cannot take the evaluation down. Usage: adversarial_worker.py <file.py> <task>
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gate.adversarial import CHECKS, run_all  # noqa: E402
from gate.run_gate import load_module, throwaway_temp  # noqa: E402


def main():
    target, task = sys.argv[1], sys.argv[2]
    result = {"load_error": None, "checks": {c: None for c in CHECKS}}
    try:
        with throwaway_temp():
            module = load_module(target, task)
            result["checks"] = run_all(module, task)
    except BaseException as e:  # includes SystemExit from model code
        result["load_error"] = f"{type(e).__name__}: {e}"[:300]
    sys.stdout.write("\n@@RESULT@@" + json.dumps(result))


if __name__ == "__main__":
    main()
