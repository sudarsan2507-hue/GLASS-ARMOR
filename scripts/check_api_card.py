"""Check that every line of the API card in config.yaml actually runs.

The card is executed as Python with a few placeholder inputs filled in.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
card = yaml.safe_load((ROOT / "config.yaml").read_text())["prompts"]["api_card"]

# Drop the title line, keep the code; fill the placeholders the card leaves open
code = "\n".join(card.splitlines()[1:])
scope = {"message": b"hello", "context": b"ctx", "input_bytes": b"x" * 32}
exec(code, scope)

assert len(scope["shared_secret"]) == 32
assert scope["ok"] is True
assert len(scope["key"]) == 32
print("API card runs OK: every line executed without error")
