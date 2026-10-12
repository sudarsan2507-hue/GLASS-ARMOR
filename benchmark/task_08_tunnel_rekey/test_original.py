"""Functional tests for the tunnel module.

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


def connect():
    state, msg1 = mod.initiator_start()
    responder, msg2 = mod.responder_accept(msg1)
    initiator = mod.initiator_finish(state, msg2)
    return initiator, responder


def test_both_directions():
    a, b = connect()
    for i in range(5):
        assert b.receive(a.send(f"ping {i}".encode())) == f"ping {i}".encode()
        assert a.receive(b.send(f"pong {i}".encode())) == f"pong {i}".encode()


def test_packets_hide_plaintext():
    a, _ = connect()
    assert b"credit card" not in a.send(b"credit card 4111")


def test_replay_rejected():
    a, b = connect()
    packet = a.send(b"pay 5 EUR")
    b.receive(packet)
    with pytest.raises(Exception):
        b.receive(packet)


def test_tampered_packet_rejected():
    a, b = connect()
    packet = bytearray(a.send(b"hello"))
    packet[-1] ^= 0x01
    with pytest.raises(Exception):
        b.receive(bytes(packet))


def test_other_tunnel_rejected():
    a1, _ = connect()
    _, b2 = connect()
    with pytest.raises(Exception):
        b2.receive(a1.send(b"hello"))


def test_rekey_both_sides():
    a, b = connect()
    b.receive(a.send(b"before"))
    a.rekey()
    b.rekey()
    assert b.receive(a.send(b"after")) == b"after"
    assert a.receive(b.send(b"reply")) == b"reply"


def test_old_packet_rejected_after_rekey():
    a, b = connect()
    old = a.send(b"old")
    a.rekey()
    b.rekey()
    with pytest.raises(Exception):
        b.receive(old)


def test_malformed_handshake_rejected():
    with pytest.raises(Exception):
        mod.responder_accept(b"\x01" * 7)
