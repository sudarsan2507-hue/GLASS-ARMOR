"""Functional tests for the cipher-suite negotiation module.

The module under test is loaded from the PQGATE_TARGET env var (default: original.py),
so the same tests run on the original, the reference migration and every variant.
"""
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


def handshake(offered=None):
    state, hello = mod.client_hello(offered)
    server_key, suite, reply = mod.server_hello(hello)
    client_key = mod.client_finish(state, reply)
    return client_key, server_key, suite


def test_keys_match():
    client_key, server_key, _ = handshake()
    assert client_key == server_key and len(client_key) == 32


def test_server_preference_wins():
    assert handshake()[2] == mod.SERVER_PREFERENCE[0]


def test_single_offered_suite():
    suite = mod.CLIENT_SUITES[-1]
    assert handshake([suite])[2] == suite


def test_new_key_each_handshake():
    assert handshake()[0] != handshake()[0]


def test_no_common_suite_rejected():
    _, hello = mod.client_hello()
    msg = json.loads(hello)
    msg["suites"] = ["RSA-RC4-MD5"]
    with pytest.raises(ValueError):
        mod.server_hello(json.dumps(msg).encode())


def test_unoffered_suite_in_reply_rejected():
    state, hello = mod.client_hello()
    _, _, reply = mod.server_hello(hello)
    msg = json.loads(reply)
    msg["suite"] = "RSA-RC4-MD5"
    with pytest.raises(ValueError):
        mod.client_finish(state, json.dumps(msg).encode())


def test_channel_roundtrip():
    client_key, server_key, _ = handshake()
    client, server = mod.Channel(client_key), mod.Channel(server_key)
    for i in range(3):
        assert server.open(client.seal(f"GET /{i}".encode())) == f"GET /{i}".encode()
        assert client.open(server.seal(b"200 OK")) == b"200 OK"


def test_channel_tamper_rejected():
    client_key, server_key, _ = handshake()
    record = bytearray(mod.Channel(client_key).seal(b"hello"))
    record[-1] ^= 0x01
    with pytest.raises(Exception):
        mod.Channel(server_key).open(bytes(record))


def test_channel_other_session_rejected():
    key1, _, _ = handshake()
    key2, _, _ = handshake()
    with pytest.raises(Exception):
        mod.Channel(key2).open(mod.Channel(key1).seal(b"hello"))
