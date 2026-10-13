"""Functional tests for the API token module.

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

NOW = 1_800_000_000


def b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def issuer():
    return mod.generate_keypair()


def test_issue_and_verify(issuer):
    token = mod.issue_token(issuer[1], {"sub": "alice", "scope": "read"}, now=NOW)
    assert isinstance(token, str) and token.count(".") == 2
    claims = mod.verify_token(issuer[0], token, now=NOW + 10)
    assert claims["sub"] == "alice" and claims["scope"] == "read"
    assert claims["exp"] == NOW + 3600 and claims["iat"] == NOW


def test_expired_token_rejected(issuer):
    token = mod.issue_token(issuer[1], {"sub": "alice"}, ttl_seconds=60, now=NOW)
    with pytest.raises(mod.InvalidToken):
        mod.verify_token(issuer[0], token, now=NOW + 61)


def test_modified_claims_rejected(issuer):
    header, _, sig = mod.issue_token(issuer[1], {"sub": "alice", "scope": "read"}, now=NOW).split(".")
    forged = b64e(json.dumps({"sub": "alice", "scope": "admin", "iat": NOW, "exp": NOW + 3600}).encode())
    with pytest.raises(mod.InvalidToken):
        mod.verify_token(issuer[0], f"{header}.{forged}.{sig}", now=NOW)


def test_other_issuer_rejected(issuer):
    _, other_private = mod.generate_keypair()
    token = mod.issue_token(other_private, {"sub": "mallory"}, now=NOW)
    with pytest.raises(mod.InvalidToken):
        mod.verify_token(issuer[0], token, now=NOW)


def test_alg_none_rejected(issuer):
    _, claims, _ = mod.issue_token(issuer[1], {"sub": "alice"}, now=NOW).split(".")
    header = b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    with pytest.raises(mod.InvalidToken):
        mod.verify_token(issuer[0], f"{header}.{claims}.", now=NOW)


@pytest.mark.parametrize("bad", ["", "abc", "a.b", "a.b.c.d"])
def test_malformed_token_rejected(issuer, bad):
    with pytest.raises(mod.InvalidToken):
        mod.verify_token(issuer[0], bad, now=NOW)


def test_truncated_signature_rejected(issuer):
    token = mod.issue_token(issuer[1], {"sub": "alice"}, now=NOW)
    with pytest.raises(mod.InvalidToken):
        mod.verify_token(issuer[0], token[:-20], now=NOW)
