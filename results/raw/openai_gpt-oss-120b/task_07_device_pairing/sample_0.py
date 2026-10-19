"""Pairing a smart‑home device with a hub (ML‑KEM‑768 + a 6‑digit verification code).

Both sides display a verification code derived from the shared pairing key and the
user confirms they match. Afterwards the hub authenticates commands to the
device with HMAC‑SHA256.

The protocol mirrors the original X25519‑based implementation but uses the
post‑quantum ML‑KEM‑768 key‑encapsulation mechanism from liboqs.

Public API (unchanged):
    device_start(device_id) -> (state, device_hello)
    parse_device_id(device_hello) -> str
    hub_respond(device_hello) -> (pairing_key, hub_hello)
    device_finish(state, hub_hello) -> pairing_key
    verification_code(pairing_key) -> str
    sign_command(pairing_key, command) -> bytes
    verify_command(pairing_key, command, tag) -> bool
"""

import hashlib
import hmac

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _pairing_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """Derive a 32‑byte pairing key from the KEM shared secret and transcript."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate pairing v1" + transcript,
    ).derive(shared_secret)


def device_start(device_id: str):
    """Start pairing. Returns (device_state, device_hello).

    device_state holds the secret key needed for decapsulation later.
    device_hello = 1‑byte id length | device id | ML‑KEM‑768 public key.
    """
    ident = device_id.encode()
    if not 0 < len(ident) < 256:
        raise ValueError("bad device id")

    # Generate a fresh ML‑KEM‑768 key pair.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    secret_key = kem.export_secret_key()         # bytes (kept private)

    hello = bytes([len(ident)]) + ident + public_key
    state = {"secret_key": secret_key, "hello": hello}
    return state, hello


def parse_device_id(device_hello: bytes) -> str:
    """Extract the device identifier from a device_hello message."""
    return device_hello[1 : 1 + device_hello[0]].decode()


def hub_respond(device_hello: bytes):
    """Answer a device hello. Returns (pairing_key, hub_hello).

    hub_hello is the ML‑KEM‑768 ciphertext (encapsulation) that the hub sends
    back to the device.
    """
    if not device_hello:
        raise ValueError("bad device hello")

    n = device_hello[0]
    peer_pub = device_hello[1 + n :]  # the device's ML‑KEM public key

    if n == 0 or len(peer_pub) == 0:
        raise ValueError("bad device hello")

    # Encapsulate a shared secret using the device's public key.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(peer_pub)

    pairing_key = _pairing_key(shared_secret, device_hello + ciphertext)
    return pairing_key, ciphertext


def device_finish(state: dict, hub_hello: bytes) -> bytes:
    """Finish pairing on the device. Returns the pairing_key."""
    if not hub_hello:
        raise ValueError("bad hub hello")

    # Decapsulate using the stored secret key.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=state["secret_key"])
    shared_secret = kem.decap_secret(hub_hello)

    pairing_key = _pairing_key(shared_secret, state["hello"] + hub_hello)
    return pairing_key


def verification_code(pairing_key: bytes) -> str:
    """6‑digit code shown on both screens."""
    digest = hmac.new(pairing_key, b"verification code", hashlib.sha256).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def sign_command(pairing_key: bytes, command: bytes) -> bytes:
    """Authenticate a command (bytes) from the hub. Returns a 32‑byte tag."""
    return hmac.new(pairing_key, command, hashlib.sha256).digest()


def verify_command(pairing_key: bytes, command: bytes, tag: bytes) -> bool:
    """Return True if tag is valid for command."""
    return hmac.compare_digest(sign_command(pairing_key, command), tag)
