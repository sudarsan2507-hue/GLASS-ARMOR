"""Functional tests for the signer factory / negotiation module.

The module under test is loaded from the PQGATE_TARGET env var (default: original.py),
so the same tests run on the original, the reference migration and every variant.
"""
import base64
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
def keys():
    return mod.get_signer(mod.DEFAULT_ALG).generate_keypair()


def test_default_is_supported():
    assert mod.DEFAULT_ALG in mod.SUPPORTED


def test_sign_and_verify(keys):
    signer = mod.get_signer(mod.DEFAULT_ALG)
    signature = signer.sign(keys[1], b"hello")
    assert signer.verify(keys[0], b"hello", signature) is True
    assert signer.verify(keys[0], b"hellO", signature) is False


def test_unknown_algorithm_rejected():
    with pytest.raises(ValueError):
        mod.get_signer("dsa-512")


def test_negotiate_common_algorithm():
    assert mod.negotiate(["dsa-512", mod.DEFAULT_ALG]) == mod.DEFAULT_ALG


def test_negotiate_no_common_algorithm():
    with pytest.raises(ValueError):
        mod.negotiate(["dsa-512", "md5-rsa"])


def test_envelope_roundtrip(keys):
    env = mod.seal_envelope(mod.DEFAULT_ALG, keys[1], b"deploy build 1234")
    assert env["alg"] == mod.DEFAULT_ALG
    assert mod.open_envelope(keys[0], env) == b"deploy build 1234"


def test_envelope_tampered_message_rejected(keys):
    env = mod.seal_envelope(mod.DEFAULT_ALG, keys[1], b"deploy build 1234")
    env["msg"] = base64.b64encode(b"deploy build 6666").decode()
    with pytest.raises(ValueError):
        mod.open_envelope(keys[0], env)


def test_envelope_disallowed_algorithm_rejected(keys):
    env = mod.seal_envelope(mod.DEFAULT_ALG, keys[1], b"x")
    env["alg"] = "none"
    with pytest.raises(ValueError):
        mod.open_envelope(keys[0], env)


def test_envelope_wrong_key_rejected(keys):
    other_public, _ = mod.get_signer(mod.DEFAULT_ALG).generate_keypair()
    env = mod.seal_envelope(mod.DEFAULT_ALG, keys[1], b"x")
    with pytest.raises(ValueError):
        mod.open_envelope(other_public, env)
