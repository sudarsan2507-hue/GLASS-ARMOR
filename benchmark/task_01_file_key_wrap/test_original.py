"""Functional tests for the file key-wrapping module.

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


@pytest.fixture(scope="module")
def alice():
    return mod.generate_keypair()


@pytest.fixture(scope="module")
def bob():
    return mod.generate_keypair()


def test_keypair_is_bytes(alice):
    public_key, private_key = alice
    assert isinstance(public_key, bytes) and isinstance(private_key, bytes)
    assert public_key != private_key


def test_wrap_unwrap_roundtrip(alice):
    data_key = os.urandom(32)
    wrapped = mod.wrap_key(alice[0], data_key)
    assert wrapped != data_key
    assert mod.unwrap_key(alice[1], wrapped) == data_key


@pytest.mark.parametrize("plaintext", [b"", b"hello", bytes(range(256)) * 400],
                         ids=["empty", "short", "100kB"])
def test_encrypt_decrypt_roundtrip(alice, plaintext):
    blob = mod.encrypt_file(alice[0], plaintext, "notes.txt")
    assert mod.decrypt_file(alice[1], blob, "notes.txt") == plaintext


def test_ciphertext_hides_plaintext(alice):
    plaintext = b"top secret quarterly numbers" * 4
    blob = mod.encrypt_file(alice[0], plaintext, "q3.txt")
    assert plaintext not in blob


def test_encryption_is_randomized(alice):
    blob1 = mod.encrypt_file(alice[0], b"same data", "a.txt")
    blob2 = mod.encrypt_file(alice[0], b"same data", "a.txt")
    assert blob1 != blob2


def test_wrong_private_key_fails(alice, bob):
    blob = mod.encrypt_file(alice[0], b"for alice only", "a.txt")
    with pytest.raises(Exception):
        mod.decrypt_file(bob[1], blob, "a.txt")


def test_tampered_ciphertext_fails(alice):
    blob = bytearray(mod.encrypt_file(alice[0], b"important", "a.txt"))
    blob[-1] ^= 0x01
    with pytest.raises(Exception):
        mod.decrypt_file(alice[1], bytes(blob), "a.txt")


def test_wrong_filename_fails(alice):
    blob = mod.encrypt_file(alice[0], b"contract", "contract.pdf")
    with pytest.raises(Exception):
        mod.decrypt_file(alice[1], blob, "other.pdf")


def test_save_and_load_file(alice, tmp_path):
    path = str(tmp_path / "report.bin")
    mod.save_encrypted(path, alice[0], b"report contents")
    assert mod.load_encrypted(path, alice[1]) == b"report contents"
    with open(path, "rb") as f:
        assert b"report contents" not in f.read()
