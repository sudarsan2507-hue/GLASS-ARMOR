"""Functional tests for the session cookie module.

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
CSRF_SECRET = b"csrf-secret-for-tests-0123456789"


def b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@pytest.fixture(scope="module")
def server():
    return mod.generate_keypair()


def test_issue_and_load(server):
    cookie, token = mod.issue_session(server[1], CSRF_SECRET, "alice", now=NOW)
    session = mod.load_session(server[0], cookie, now=NOW + 5)
    assert session["user"] == "alice" and session["exp"] == NOW + 3600
    assert isinstance(token, str)


def test_session_ids_are_unique(server):
    sids = {mod.load_session(server[0], mod.issue_session(server[1], CSRF_SECRET, "a", now=NOW)[0],
                             now=NOW)["sid"] for _ in range(20)}
    assert len(sids) == 20


def test_expired_session_rejected(server):
    cookie, _ = mod.issue_session(server[1], CSRF_SECRET, "alice", ttl_seconds=10, now=NOW)
    assert mod.load_session(server[0], cookie, now=NOW + 11) is None


def test_changed_user_rejected(server):
    cookie, _ = mod.issue_session(server[1], CSRF_SECRET, "alice", now=NOW)
    payload_b64, sig_b64 = cookie.split(".")
    session = json.loads(b64d(payload_b64))
    session["user"] = "admin"
    forged = b64e(json.dumps(session, sort_keys=True).encode()) + "." + sig_b64
    assert mod.load_session(server[0], forged, now=NOW) is None


@pytest.mark.parametrize("bad", ["", "nodot", "a.b", "a.b.c"])
def test_garbage_cookie_rejected(server, bad):
    assert mod.load_session(server[0], bad, now=NOW) is None


def test_other_server_key_rejected(server):
    other_public, _ = mod.generate_keypair()
    cookie, _ = mod.issue_session(server[1], CSRF_SECRET, "alice", now=NOW)
    assert mod.load_session(other_public, cookie, now=NOW) is None


def test_csrf_token_valid(server):
    cookie, token = mod.issue_session(server[1], CSRF_SECRET, "alice", now=NOW)
    session = mod.load_session(server[0], cookie, now=NOW)
    assert mod.check_csrf(CSRF_SECRET, session, token) is True


def test_csrf_token_from_other_session_rejected(server):
    cookie1, _ = mod.issue_session(server[1], CSRF_SECRET, "alice", now=NOW)
    _, token2 = mod.issue_session(server[1], CSRF_SECRET, "alice", now=NOW)
    session1 = mod.load_session(server[0], cookie1, now=NOW)
    assert mod.check_csrf(CSRF_SECRET, session1, token2) is False
