"""Functional tests for the audit log module.

The module under test is loaded from the PQGATE_TARGET env var (default: original.py),
so the same tests run on the original, the reference migration and every variant.
"""
import copy
import importlib.util
import os
from pathlib import Path

import pytest

HERE = Path(__file__).parent
TARGET = os.environ.get("PQGATE_TARGET", str(HERE / "original.py"))
_spec = importlib.util.spec_from_file_location("target", TARGET)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

EVENTS = ["alice logged in", "alice exported report.csv", "bob changed role of carol", "alice logged out"]


@pytest.fixture(scope="module")
def keys():
    return mod.generate_keypair()


@pytest.fixture
def entries(keys):
    log = mod.AuditLog(keys[1])
    for e in EVENTS:
        log.append(e)
    return log.entries


def test_append_returns_entry(keys):
    log = mod.AuditLog(keys[1])
    entry = log.append("system start")
    assert entry["seq"] == 0 and entry["event"] == "system start" and entry["prev"] == "0" * 64
    assert log.entries == [entry]


def test_valid_log(keys, entries):
    assert len(entries) == 4
    assert mod.verify_log(keys[0], entries) is True


def test_empty_log_is_valid(keys):
    assert mod.verify_log(keys[0], []) is True


def test_chain_links(entries):
    assert entries[1]["prev"] != entries[2]["prev"]
    assert all(len(e["prev"]) == 64 for e in entries)


def test_edited_event_rejected(keys, entries):
    tampered = copy.deepcopy(entries)
    tampered[1]["event"] = "alice exported nothing"
    assert mod.verify_log(keys[0], tampered) is False


def test_deleted_entry_rejected(keys, entries):
    assert mod.verify_log(keys[0], entries[:1] + entries[2:]) is False


def test_swapped_entries_rejected(keys, entries):
    assert mod.verify_log(keys[0], [entries[0], entries[2], entries[1], entries[3]]) is False


def test_wrong_key_rejected(entries):
    other_public, _ = mod.generate_keypair()
    assert mod.verify_log(other_public, entries) is False


def test_missing_field_rejected(keys, entries):
    tampered = copy.deepcopy(entries)
    del tampered[2]["signature"]
    assert mod.verify_log(keys[0], tampered) is False
