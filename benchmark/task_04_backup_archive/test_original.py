"""Functional tests for the multi-recipient backup archive module.

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

FILES = {"db.sql": b"INSERT INTO users VALUES ('alice');", "photo.jpg": bytes(range(256)) * 20,
         "empty.txt": b""}


@pytest.fixture(scope="module")
def keys():
    return {name: mod.generate_keypair() for name in ("alice", "bob", "eve")}


@pytest.fixture(scope="module")
def archive(keys):
    recipients = {"alice": keys["alice"][0], "bob": keys["bob"][0]}
    return mod.create_archive(recipients, FILES)


def test_archive_is_bytes(archive):
    assert isinstance(archive, bytes)


def test_list_files(archive):
    assert mod.list_files(archive) == sorted(FILES)


@pytest.mark.parametrize("who", ["alice", "bob"])
def test_each_recipient_can_restore(archive, keys, who):
    assert mod.restore_archive(archive, who, keys[who][1]) == FILES


def test_non_recipient_cannot_restore(archive, keys):
    with pytest.raises(Exception):
        mod.restore_archive(archive, "eve", keys["eve"][1])


def test_wrong_private_key_fails(archive, keys):
    with pytest.raises(Exception):
        mod.restore_archive(archive, "alice", keys["eve"][1])


def test_plaintext_not_in_archive(archive):
    assert b"alice" not in archive.replace(b'"alice"', b"")
    assert b"INSERT INTO" not in archive


def test_tampered_file_rejected(archive, keys):
    doc = json.loads(archive)
    raw = bytearray(base64.b64decode(doc["files"]["db.sql"]))
    raw[-1] ^= 0x01
    doc["files"]["db.sql"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(Exception):
        mod.restore_archive(json.dumps(doc).encode(), "alice", keys["alice"][1])


def test_swapped_file_names_rejected(archive, keys):
    doc = json.loads(archive)
    doc["files"]["db.sql"], doc["files"]["photo.jpg"] = doc["files"]["photo.jpg"], doc["files"]["db.sql"]
    with pytest.raises(Exception):
        mod.restore_archive(json.dumps(doc).encode(), "alice", keys["alice"][1])


def test_two_archives_differ(keys):
    recipients = {"alice": keys["alice"][0]}
    assert mod.create_archive(recipients, {"a": b"x"}) != mod.create_archive(recipients, {"a": b"x"})
