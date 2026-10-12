"""Functional tests for the device pairing module.

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


def pair(device_id="thermostat-42"):
    state, device_hello = mod.device_start(device_id)
    hub_key, hub_hello = mod.hub_respond(device_hello)
    device_key = mod.device_finish(state, hub_hello)
    return device_key, hub_key


def test_both_sides_get_same_key():
    device_key, hub_key = pair()
    assert device_key == hub_key and len(device_key) == 32


def test_each_pairing_gives_new_key():
    assert pair()[0] != pair()[0]


def test_device_id_in_hello():
    _, hello = mod.device_start("lamp-7")
    assert mod.parse_device_id(hello) == "lamp-7"


@pytest.mark.parametrize("bad_id", ["", "x" * 300])
def test_bad_device_id_rejected(bad_id):
    with pytest.raises(ValueError):
        mod.device_start(bad_id)


def test_malformed_device_hello_rejected():
    with pytest.raises(Exception):
        mod.hub_respond(b"\x03abc" + b"\x00" * 10)


def test_verification_codes_match():
    device_key, hub_key = pair()
    code = mod.verification_code(device_key)
    assert code == mod.verification_code(hub_key)
    assert len(code) == 6 and code.isdigit()


def test_command_roundtrip():
    device_key, hub_key = pair()
    tag = mod.sign_command(hub_key, b"unlock front door")
    assert mod.verify_command(device_key, b"unlock front door", tag) is True


def test_tampered_command_rejected():
    device_key, hub_key = pair()
    tag = mod.sign_command(hub_key, b"set temp 20")
    assert mod.verify_command(device_key, b"set temp 30", tag) is False


def test_tag_from_other_pairing_rejected():
    key1, _ = pair()
    key2, _ = pair()
    tag = mod.sign_command(key1, b"unlock front door")
    assert mod.verify_command(key2, b"unlock front door", tag) is False
