"""Functional tests for the session handshake + secure channel module.

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


def handshake():
    state, client_hello = mod.client_start()
    server_key, server_hello = mod.server_respond(client_hello)
    client_key = mod.client_finish(state, server_hello)
    return client_key, server_key


def test_both_sides_get_same_key():
    client_key, server_key = handshake()
    assert client_key == server_key
    assert isinstance(client_key, bytes) and len(client_key) == 32


def test_each_handshake_gives_new_key():
    assert handshake()[0] != handshake()[0]


def test_hellos_are_bytes():
    state, client_hello = mod.client_start()
    _, server_hello = mod.server_respond(client_hello)
    assert isinstance(client_hello, bytes) and isinstance(server_hello, bytes)


def test_malformed_client_hello_rejected():
    with pytest.raises(Exception):
        mod.server_respond(b"too short")


def test_channel_roundtrip_both_directions():
    client_key, server_key = handshake()
    client, server = mod.SecureChannel(client_key), mod.SecureChannel(server_key)
    for i in range(5):
        msg = f"message {i}".encode()
        assert server.decrypt(client.encrypt(msg)) == msg
        assert client.decrypt(server.encrypt(msg)) == msg


def test_channel_hides_plaintext():
    key, _ = handshake()
    assert b"password=hunter2" not in mod.SecureChannel(key).encrypt(b"password=hunter2")


def test_tampered_message_rejected():
    key, _ = handshake()
    channel = mod.SecureChannel(key)
    message = bytearray(channel.encrypt(b"transfer 10 EUR"))
    message[-1] ^= 0x01
    with pytest.raises(Exception):
        channel.decrypt(bytes(message))


def test_message_from_other_session_rejected():
    key1, _ = handshake()
    key2, _ = handshake()
    message = mod.SecureChannel(key1).encrypt(b"hello")
    with pytest.raises(Exception):
        mod.SecureChannel(key2).decrypt(message)


def test_wrong_aad_rejected():
    key, _ = handshake()
    channel = mod.SecureChannel(key)
    message = channel.encrypt(b"hello", aad=b"header-1")
    assert channel.decrypt(message, aad=b"header-1") == b"hello"
    with pytest.raises(Exception):
        channel.decrypt(message, aad=b"header-2")
