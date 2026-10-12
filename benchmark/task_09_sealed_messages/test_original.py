"""Functional tests for the sealed messages module.

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
def bob():
    return mod.generate_identity()


@pytest.fixture(scope="module")
def carol():
    return mod.generate_identity()


def test_identity_is_bytes(bob):
    assert isinstance(bob[0], bytes) and isinstance(bob[1], bytes) and bob[0] != bob[1]


def test_seal_and_open(bob):
    sealed = mod.seal(bob[0], "alice", "lunch at 12?")
    assert mod.open_sealed(bob[1], sealed) == ("alice", "lunch at 12?")


def test_unicode_and_empty_text(bob):
    assert mod.open_sealed(bob[1], mod.seal(bob[0], "zoë", "")) == ("zoë", "")
    assert mod.open_sealed(bob[1], mod.seal(bob[0], "a", "héllo 👋")) == ("a", "héllo 👋")


def test_sealed_hides_sender_and_text(bob):
    sealed = mod.seal(bob[0], "alice", "meet at the station")
    assert b"alice" not in sealed and b"station" not in sealed


def test_sealing_is_randomized(bob):
    assert mod.seal(bob[0], "alice", "hi") != mod.seal(bob[0], "alice", "hi")


def test_other_recipient_cannot_open(bob, carol):
    sealed = mod.seal(bob[0], "alice", "for bob only")
    with pytest.raises(Exception):
        mod.open_sealed(carol[1], sealed)


def test_tampered_message_rejected(bob):
    sealed = bytearray(mod.seal(bob[0], "alice", "hello"))
    sealed[-1] ^= 0x01
    with pytest.raises(Exception):
        mod.open_sealed(bob[1], bytes(sealed))


def test_short_message_rejected(bob):
    with pytest.raises(Exception):
        mod.open_sealed(bob[1], b"\x00" * 20)


def test_fingerprint(bob, carol):
    fp = mod.fingerprint(bob[0])
    assert fp == mod.fingerprint(bob[0]) and fp != mod.fingerprint(carol[0])
    assert len(fp.split()) == 5
