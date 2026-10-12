"""Functional tests for the document signing module.

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

DOC = b"I, Alice, agree to pay Bob 100 EUR on 1 December 2026."


@pytest.fixture(scope="module")
def alice():
    return mod.generate_keypair()


@pytest.fixture(scope="module")
def mallory():
    return mod.generate_keypair()


def test_keypair_is_bytes(alice):
    public_key, private_key = alice
    assert isinstance(public_key, bytes) and isinstance(private_key, bytes)
    assert public_key != private_key


@pytest.mark.parametrize("purpose", ["general", "contract", "invoice"])
def test_sign_and_verify(alice, purpose):
    signature = mod.sign_document(alice[1], DOC, purpose)
    assert isinstance(signature, bytes)
    assert mod.verify_document(alice[0], DOC, signature, purpose) is True


def test_default_purpose(alice):
    signature = mod.sign_document(alice[1], DOC)
    assert mod.verify_document(alice[0], DOC, signature) is True


def test_tampered_document_rejected(alice):
    signature = mod.sign_document(alice[1], DOC, "contract")
    tampered = DOC.replace(b"100", b"900")
    assert mod.verify_document(alice[0], tampered, signature, "contract") is False


def test_tampered_signature_rejected(alice):
    signature = bytearray(mod.sign_document(alice[1], DOC, "contract"))
    signature[10] ^= 0x01
    assert mod.verify_document(alice[0], DOC, bytes(signature), "contract") is False


def test_wrong_public_key_rejected(alice, mallory):
    signature = mod.sign_document(mallory[1], DOC, "contract")
    assert mod.verify_document(alice[0], DOC, signature, "contract") is False


@pytest.mark.parametrize("bad_signature", [b"", b"\x00" * 16, b"garbage" * 100],
                         ids=["empty", "short", "garbage"])
def test_malformed_signature_returns_false(alice, bad_signature):
    assert mod.verify_document(alice[0], DOC, bad_signature, "contract") is False


def test_sign_and_verify_file(alice, tmp_path):
    path = str(tmp_path / "contract.txt")
    with open(path, "wb") as f:
        f.write(DOC)
    mod.sign_file(path, alice[1], "contract")
    assert os.path.exists(path + ".sig")
    assert mod.verify_file(path, alice[0], "contract") is True
    with open(path, "wb") as f:
        f.write(DOC + b" (amended)")
    assert mod.verify_file(path, alice[0], "contract") is False
