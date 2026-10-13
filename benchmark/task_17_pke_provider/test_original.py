"""Functional tests for the config-chosen public-key encryption module.

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
def provider():
    return mod.get_provider(mod.DEFAULT_CONFIG)


@pytest.fixture(scope="module")
def keys(provider):
    return provider.generate_keypair()


def test_default_provider_is_available(provider):
    assert provider.name in mod.available_algorithms()


def test_empty_config_uses_default(provider):
    assert mod.get_provider({}).name == provider.name


def test_unknown_algorithm_rejected():
    with pytest.raises(ValueError):
        mod.get_provider({"pke": "rot13"})


@pytest.mark.parametrize("data", [b"", b"hello", bytes(range(256)) * 100], ids=["empty", "short", "25kB"])
def test_roundtrip(provider, keys, data):
    assert provider.decrypt(keys[1], provider.encrypt(keys[0], data)) == data


def test_encryption_is_randomized(provider, keys):
    assert provider.encrypt(keys[0], b"same") != provider.encrypt(keys[0], b"same")


def test_ciphertext_hides_plaintext(provider, keys):
    assert b"salary: 85000" not in provider.encrypt(keys[0], b"salary: 85000")


def test_wrong_key_fails(provider, keys):
    _, other_private = provider.generate_keypair()
    with pytest.raises(Exception):
        provider.decrypt(other_private, provider.encrypt(keys[0], b"secret"))


def test_tampered_ciphertext_fails(provider, keys):
    blob = bytearray(provider.encrypt(keys[0], b"secret"))
    blob[-1] ^= 0x01
    with pytest.raises(Exception):
        provider.decrypt(keys[1], bytes(blob))
