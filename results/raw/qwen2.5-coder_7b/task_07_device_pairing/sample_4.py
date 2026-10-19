"""Pairing a smart-home device with a hub (ML-KEM + a 6-digit verification code).

    state, device_hello = device_start(device_id)
    hub_key, hub_hello = hub_respond(device_hello)       # on the hub
    device_key = device_finish(state, hub_hello)         # on the device
Both sides display verification_code(key) and the user confirms they match.
Afterwards the hub authenticates commands to the device with HMAC-SHA256.

device_hello = 1-byte id length | device id | ML-KEM public key (32)
hub_hello    = ML-KEM public key (32)
"""
import hashlib
import hmac

from oqs import KeyEncapsulation
from cryptography.hazmat.primitives import hashes, serialization


def _raw(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _pairing_key(shared_secret, transcript):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate pairing v1" + transcript).derive(shared_secret)


def device_start(device_id):
    """Start pairing. Returns (device_state, device_hello)."""
    ident = device_id.encode()
    if not 0 < len(ident) < 256:
        raise ValueError("bad device id")
    kem = KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()[0]
    hello = bytes([len(ident)]) + ident + _raw(public_key)
    return {"kem": kem, "hello": hello}, hello


def parse_device_id(device_hello):
    return device_hello[1:1 + device_hello[0]].decode()


def hub_respond(device_hello):
    """Answer a device hello. Returns (pairing_key, hub_hello)."""
    n = device_hello[0] if device_hello else 0
    peer = device_hello[1 + n:]
    if n == 0 or len(peer) != 32:
        raise ValueError("bad device hello")
    kem = KeyEncapsulation("ML-KEM-768")
    hub_hello = _raw(kem.generate_keypair()[0])
    shared = kem.decap_secret(peer)
    return _pairing_key(shared, device_hello + hub_hello), hub_hello


def device_finish(state, hub_hello):
    """Finish pairing on the device. Returns pairing_key."""
    if len(hub_hello) != 32:
        raise ValueError("bad hub hello")
    shared = state["kem"].decap_secret(hub_hello)
    return _pairing_key(shared, state["hello"] + hub_hello)


def verification_code(pairing_key):
    """6-digit code shown on both screens."""
    digest = hmac.new(pairing_key, b"verification code", hashlib.sha256).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def sign_command(pairing_key, command):
    """Authenticate a command (bytes) from the hub. Returns a 32-byte tag."""
    return hmac.new(pairing_key, command, hashlib.sha256).digest()


def verify_command(pairing_key, command, tag):
    """Return True if tag is valid for command."""
    return hmac.compare_digest(sign_command(pairing_key, command), tag)
