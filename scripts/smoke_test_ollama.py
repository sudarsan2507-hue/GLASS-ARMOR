"""Smoke test: send one short prompt to each model in config.yaml and print the reply."""
import sys
import time
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
config = yaml.safe_load((ROOT / "config.yaml").read_text())
url = config["ollama"]["url"]
gen = config["generation"]

# Optional: pass model names on the command line to test only those
wanted = sys.argv[1:] or [m["name"] for m in config["models"]]

# Log name, tag and size of every installed model
installed = {m["name"]: m for m in requests.get(f"{url}/api/tags", timeout=30).json()["models"]}

all_ok = True
for name in wanted:
    if name not in installed:
        print(f"[{name}] NOT INSTALLED")
        all_ok = False
        continue
    info = installed[name]
    print(f"[{name}] digest={info['digest'][:12]} size={info['size'] / 1e9:.2f} GB")
    body = {
        "model": name,
        "prompt": "Reply with one short sentence: what is ML-KEM?",
        "stream": False,
        "options": {"temperature": gen["temperature"], "seed": gen["seeds"][0],
                    "num_ctx": gen["num_ctx"]},
    }
    start = time.time()
    try:
        r = requests.post(f"{url}/api/generate", json=body, timeout=config["ollama"]["timeout_s"])
        r.raise_for_status()
        reply = r.json()["response"].strip()
        print(f"  reply ({time.time() - start:.1f}s): {reply}")
    except requests.RequestException as e:
        print(f"  FAILED ({time.time() - start:.1f}s): {e}")
        all_ok = False

print("OLLAMA SMOKE TEST", "PASSED" if all_ok else "FAILED")
sys.exit(0 if all_ok else 1)
