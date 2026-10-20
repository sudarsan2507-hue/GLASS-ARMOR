"""Pairing a smart‑home device with a hub (ML‑KEM‑768 + a 6‑digit verification code).

Both sides exchange a KEM public key (device) and a ciphertext (hub).  The
resulting shared secret is turned into a 32‑byte pairing key with HKDF.
The pairing key is displayed as a 6‑digit verification code and later used
to HMAC‑authenticate commands.

The public API (device_start, hub_respond, device_finish, …) is unchanged
so existing tests continue to work.
"""

import hashlib
import hmac

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --------------------------------------------------------------------------- #
# Helper utilities
# --------------------------------------------------------------------------- #
def _raw(public_key_bytes: bytes) -> bytes:
    """Return the raw bytes of a KEM public key (already raw)."""
    return public_key_bytes


def _pairing_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """Derive a 32‑byte pairing key from the KEM shared secret and transcript."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate pairing v1" + transcript,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
# Device side
# --------------------------------------------------------------------------- #
def device_start(device_id: str):
    """Start pairing. Returns (device_state, device_hello).

    device_hello layout:
        1‑byte id length | device id (utf‑8) | KEM public key (bytes)
    """
    ident = device_id.encode()
    if not 0 < len(ident) < 256:
        raise ValueError("bad device id")

    # Generate a fresh ML‑KEM‑768 keypair
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    secret_key = kem.export_secret_key()         # bytes (needed for decapsulation)

    hello = bytes([len(ident)]) + ident + _raw(public_key)
    state = {
        "kem": kem,               # holds the generated keypair (public part only)
        "secret_key": secret_key, # stored for later decapsulation
        "hello": hello,
    }
    return state, hello


def parse_device_id(device_hello: bytes) -> str:
    """Extract the device identifier from a device_hello message."""
    return device_hello[1 : 1 + device_hello[0]].decode()


# --------------------------------------------------------------------------- #
# Hub side
# --------------------------------------------------------------------------- #
def hub_respond(device_hello: bytes):
    """Answer a device hello. Returns (pairing_key, hub_hello).

    hub_hello is the KEM ciphertext that the hub sends back to the device.
    """
    n = device_hello[0] if device_hello else 0
    peer_pub = device_hello[1 + n :]  # device's KEM public key
    if n == 0 or len(peer_pub) != 1184:  # ML‑KEM‑768 public key size
        raise ValueError("bad device hello")

    # Hub generates its own KEM keypair (public key not needed to send)
    hub_kem = oqs.KeyEncapsulation("ML-KEM-768")
    hub_kem.generate_keypair()  # we only need the secret key for decapsulation later (if ever)

    # Encapsulate using the device's public key
    ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(peer_pub)

    # Derive the pairing key from the shared secret and the transcript
    pairing_key = _pairing_key(shared_secret, device_hello + ciphertext)

    # hub_hello is the ciphertext that the device will decapsulate
    hub_hello = ciphertext
    return pairing_key, hub_hello


# --------------------------------------------------------------------------- #
# Device finalisation
# --------------------------------------------------------------------------- #
def device_finish(state: dict, hub_hello: bytes):
    """Finish pairing on the device. Returns the pairing_key."""
    if not isinstance(hub_hello, (bytes, bytearray)):
        raise ValueError("bad hub hello")
    # Decapsulate using the stored secret key
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=state["secret_key"])
    shared_secret = kem.decap_secret(hub_hello)

    # Derive the same pairing key as the hub
    return _pairing_key(shared_secret, state["hello"] + hub_hello)


# --------------------------------------------------------------------------- #
# User‑visible utilities
# --------------------------------------------------------------------------- #
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
