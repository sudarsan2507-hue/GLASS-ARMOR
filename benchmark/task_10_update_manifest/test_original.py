"""Functional tests for the update manifest module.

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

PACKAGE = b"\x7fELF" + bytes(range(256)) * 10


@pytest.fixture(scope="module")
def server():
    return mod.generate_keypair()


@pytest.fixture(scope="module")
def attacker():
    return mod.generate_keypair()


def test_valid_release(server):
    manifest = mod.sign_release(server[1], "app", "1.4.2", PACKAGE)
    assert isinstance(manifest, bytes)
    assert mod.verify_release(server[0], PACKAGE, manifest) is True


def test_manifest_fields(server):
    m = json.loads(mod.sign_release(server[1], "app", "1.4.2", PACKAGE))
    assert m["name"] == "app" and m["version"] == "1.4.2" and len(m["sha256"]) == 64


def test_tampered_package_rejected(server):
    manifest = mod.sign_release(server[1], "app", "1.4.2", PACKAGE)
    assert mod.verify_release(server[0], PACKAGE + b"\x90", manifest) is False


def test_tampered_signature_rejected(server):
    m = json.loads(mod.sign_release(server[1], "app", "1.4.2", PACKAGE))
    sig = bytearray(base64.b64decode(m["signature"]))
    sig[5] ^= 0x01
    m["signature"] = base64.b64encode(bytes(sig)).decode()
    assert mod.verify_release(server[0], PACKAGE, json.dumps(m).encode()) is False


def test_attacker_key_rejected(server, attacker):
    manifest = mod.sign_release(attacker[1], "app", "9.9.9", PACKAGE)
    assert mod.verify_release(server[0], PACKAGE, manifest) is False


def test_garbage_manifest_rejected(server):
    assert mod.verify_release(server[0], PACKAGE, b"{}") is False


def test_install_newer_version(server):
    manifest = mod.sign_release(server[1], "app", "1.10.0", PACKAGE)
    assert mod.should_install(server[0], PACKAGE, manifest, "1.9.3") is True


def test_refuse_older_or_same_version(server):
    manifest = mod.sign_release(server[1], "app", "1.4.2", PACKAGE)
    assert mod.should_install(server[0], PACKAGE, manifest, "1.4.2") is False
    assert mod.should_install(server[0], PACKAGE, manifest, "2.0.0") is False
