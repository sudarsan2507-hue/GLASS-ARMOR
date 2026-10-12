"""Functional tests for the password vault module.

The module under test is loaded from the PQGATE_TARGET env var (default: original.py),
so the same tests run on the original, the reference migration and every variant.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path

import pytest

HERE = Path(__file__).parent
TARGET = os.environ.get("PQGATE_TARGET", str(HERE / "original.py"))
_spec = importlib.util.spec_from_file_location("target", TARGET)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


@pytest.fixture(scope="module")
def owner():
    return mod.generate_keypair()


@pytest.fixture(scope="module")
def stranger():
    return mod.generate_keypair()


@pytest.fixture
def vault(owner):
    v = mod.new_vault(owner[0])
    key = mod.unlock(v, owner[1])
    v = mod.add_entry(v, key, "email", "correct horse battery staple")
    v = mod.add_entry(v, key, "bank", "PIN 4821")
    return v


def test_new_vault_is_empty(owner):
    v = mod.new_vault(owner[0])
    assert isinstance(v, bytes)
    assert mod.list_entries(v) == []


def test_unlock_returns_key(owner, vault):
    key = mod.unlock(vault, owner[1])
    assert isinstance(key, bytes) and len(key) == 32


def test_add_and_get_entries(owner, vault):
    key = mod.unlock(vault, owner[1])
    assert mod.list_entries(vault) == ["bank", "email"]
    assert mod.get_entry(vault, key, "email") == "correct horse battery staple"
    assert mod.get_entry(vault, key, "bank") == "PIN 4821"


def test_overwrite_entry(owner, vault):
    key = mod.unlock(vault, owner[1])
    v2 = mod.add_entry(vault, key, "bank", "PIN 0000")
    assert mod.get_entry(v2, key, "bank") == "PIN 0000"


def test_secrets_not_in_vault_bytes(vault):
    assert b"correct horse" not in vault and b"4821" not in vault


def test_wrong_private_key_rejected(vault, stranger):
    with pytest.raises(mod.WrongKeyError):
        mod.unlock(vault, stranger[1])


def test_missing_entry_raises(owner, vault):
    key = mod.unlock(vault, owner[1])
    with pytest.raises(KeyError):
        mod.get_entry(vault, key, "nope")


def test_tampered_entry_rejected(owner, vault):
    key = mod.unlock(vault, owner[1])
    doc = json.loads(vault)
    raw = bytearray(base64.b64decode(doc["entries"]["bank"]))
    raw[-1] ^= 0x01
    doc["entries"]["bank"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(Exception):
        mod.get_entry(json.dumps(doc).encode(), key, "bank")


def test_moved_entry_rejected(owner, vault):
    key = mod.unlock(vault, owner[1])
    doc = json.loads(vault)
    doc["entries"]["email"] = doc["entries"]["bank"]
    with pytest.raises(Exception):
        mod.get_entry(json.dumps(doc).encode(), key, "email")


def test_tampered_check_value_rejected(owner, vault):
    doc = json.loads(vault)
    doc["check"] = "00" * 32
    with pytest.raises(mod.WrongKeyError):
        mod.unlock(json.dumps(doc).encode(), owner[1])
