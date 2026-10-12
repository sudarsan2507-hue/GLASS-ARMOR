"""Functional tests for the sealed-secrets module.

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

SECRETS = {"DB_PASSWORD": "s3cr3t-pa55", "API_KEY": "ak_live_12345"}


@pytest.fixture(scope="module")
def cluster():
    return mod.generate_keypair()


@pytest.fixture(scope="module")
def other_cluster():
    return mod.generate_keypair()


def test_seal_unseal_roundtrip(cluster):
    token = mod.seal(cluster[0], SECRETS, "prod")
    assert isinstance(token, str)
    assert mod.unseal(cluster[1], token, "prod") == SECRETS


def test_empty_secrets(cluster):
    assert mod.unseal(cluster[1], mod.seal(cluster[0], {}, "dev"), "dev") == {}


def test_token_hides_secrets(cluster):
    token = mod.seal(cluster[0], SECRETS, "prod")
    raw = base64.urlsafe_b64decode(token.partition(".")[2])
    assert b"s3cr3t" not in raw and b"ak_live" not in raw


def test_tokens_are_randomized(cluster):
    assert mod.seal(cluster[0], SECRETS, "prod") != mod.seal(cluster[0], SECRETS, "prod")


def test_wrong_environment_rejected(cluster):
    token = mod.seal(cluster[0], SECRETS, "staging")
    with pytest.raises(Exception):
        mod.unseal(cluster[1], token, "prod")


def test_wrong_cluster_key_rejected(cluster, other_cluster):
    token = mod.seal(cluster[0], SECRETS, "prod")
    with pytest.raises(Exception):
        mod.unseal(other_cluster[1], token, "prod")


def test_tampered_token_rejected(cluster):
    token = mod.seal(cluster[0], SECRETS, "prod")
    version, _, body = token.partition(".")
    raw = bytearray(base64.urlsafe_b64decode(body))
    raw[-1] ^= 0x01
    with pytest.raises(Exception):
        mod.unseal(cluster[1], version + "." + base64.urlsafe_b64encode(bytes(raw)).decode(), "prod")


def test_unknown_version_rejected(cluster):
    token = mod.seal(cluster[0], SECRETS, "prod")
    with pytest.raises(Exception):
        mod.unseal(cluster[1], "v9." + token.partition(".")[2], "prod")


def test_rotate(cluster, other_cluster):
    token = mod.seal(cluster[0], SECRETS, "prod")
    new_token = mod.rotate(cluster[1], other_cluster[0], token, "prod")
    assert mod.unseal(other_cluster[1], new_token, "prod") == SECRETS


def test_load_into_env(cluster):
    environ = {"PATH": "/usr/bin"}
    names = mod.load_into_env(cluster[1], mod.seal(cluster[0], SECRETS, "prod"), "prod", environ)
    assert names == ["API_KEY", "DB_PASSWORD"]
    assert environ["DB_PASSWORD"] == "s3cr3t-pa55" and environ["PATH"] == "/usr/bin"
