"""Functional tests for the policy-driven encryption module.

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
def policy():
    return mod.load_policy(mod.DEFAULT_POLICY)


@pytest.fixture(scope="module")
def keys(policy):
    return policy.generate_keypair()


def test_default_policy_loads(policy):
    assert policy.aead == "aes-256-gcm" and isinstance(policy.kex, str)


def test_roundtrip(policy, keys):
    blob = policy.encrypt(keys[0], b"quarterly report", b"doc-17")
    assert policy.decrypt(keys[1], blob, b"doc-17") == b"quarterly report"


def test_chacha_policy(policy, keys):
    chacha = mod.load_policy(f"kex={policy.kex}; aead=chacha20-poly1305")
    assert chacha.decrypt(keys[1], chacha.encrypt(keys[0], b"hi")) == b"hi"


def test_whitespace_tolerant():
    p = mod.load_policy("  aead = chacha20-poly1305 ;  ")
    assert p.aead == "chacha20-poly1305"


@pytest.mark.parametrize("text", ["kex=dh-512", "aead=des-cbc", "kex", "aead=aes-256-gcm; nonsense"])
def test_bad_policy_rejected(text):
    with pytest.raises(ValueError):
        mod.load_policy(text)


def test_randomized(policy, keys):
    assert policy.encrypt(keys[0], b"x") != policy.encrypt(keys[0], b"x")


def test_wrong_aad_rejected(policy, keys):
    blob = policy.encrypt(keys[0], b"data", b"doc-1")
    with pytest.raises(Exception):
        policy.decrypt(keys[1], blob, b"doc-2")


def test_wrong_key_rejected(policy, keys):
    _, other_private = policy.generate_keypair()
    with pytest.raises(Exception):
        policy.decrypt(other_private, policy.encrypt(keys[0], b"data"))


def test_tampered_rejected(policy, keys):
    blob = bytearray(policy.encrypt(keys[0], b"data"))
    blob[-1] ^= 0x01
    with pytest.raises(Exception):
        policy.decrypt(keys[1], bytes(blob))
