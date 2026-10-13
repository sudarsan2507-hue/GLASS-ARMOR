"""Functional tests for the webhook signature module.

The module under test is loaded from the PQGATE_TARGET env var (default: original.py),
so the same tests run on the original, the reference migration and every variant.
"""
import importlib.util
import os
from pathlib import Path

import pytest

HERE = Path(__file__).parent
TARGET = os.environ.get("PQGATE_TARGET", str(HERE / "original.py"))
_spec = importlib.util.spec_from_file_location("target", TARGET)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

NOW = 1_800_000_000
BODY = b'{"event": "payment.succeeded", "amount": 4200, "currency": "eur"}'


@pytest.fixture(scope="module")
def sender():
    return mod.generate_keypair()


@pytest.fixture(scope="module")
def keys(sender):
    return {mod.SCHEME: sender[0]}


def test_valid_webhook(sender, keys):
    header = mod.sign_webhook(sender[1], BODY, timestamp=NOW)
    assert header.startswith(f"t={NOW},")
    assert mod.verify_webhook(keys, BODY, header, now=NOW + 3) is True


def test_old_webhook_rejected(sender, keys):
    header = mod.sign_webhook(sender[1], BODY, timestamp=NOW - 301)
    assert mod.verify_webhook(keys, BODY, header, now=NOW) is False


def test_custom_tolerance(sender, keys):
    header = mod.sign_webhook(sender[1], BODY, timestamp=NOW - 600)
    assert mod.verify_webhook(keys, BODY, header, now=NOW, tolerance=900) is True


def test_modified_body_rejected(sender, keys):
    header = mod.sign_webhook(sender[1], BODY, timestamp=NOW)
    assert mod.verify_webhook(keys, BODY.replace(b"4200", b"9999"), header, now=NOW) is False


def test_other_sender_rejected(keys):
    _, other_private = mod.generate_keypair()
    header = mod.sign_webhook(other_private, BODY, timestamp=NOW)
    assert mod.verify_webhook(keys, BODY, header, now=NOW) is False


def test_missing_key_for_scheme_rejected(sender):
    header = mod.sign_webhook(sender[1], BODY, timestamp=NOW)
    assert mod.verify_webhook({}, BODY, header, now=NOW) is False


@pytest.mark.parametrize("bad", ["", "t=abc", f"t={NOW}", f"t={NOW},v1=", f"t={NOW},v2=!!!", "garbage"])
def test_malformed_header_rejected(keys, bad):
    assert mod.verify_webhook(keys, BODY, bad, now=NOW) is False
