"""Pairing a smart‑home device with a hub (ML‑KEM‑768 + a 6‑digit verification code).

Both sides exchange a KEM public key / ciphertext, derive a shared secret,
run HKDF and display a short verification code that the user confirms.
After pairing the hub authenticates commands to the device with HMAC‑SHA256.

The public API (device_start, parse_device_id, hub_respond, device_finish,
verification_code, sign_command, verify_command) is unchanged, so existing
tests continue to work.
"""

import hashlib
import hmac

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Helper utilities
# --------------------------------------------------------------------------- #
def _pairing_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """
    Derive a 32‑byte pairing key from the KEM shared secret and the full
    transcript (device_hello || hub_hello) using HKDF‑SHA256.
    """
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
    """
    Start the pairing process on the device.

    Returns
    -------
    (state, device_hello)
        * ``state`` – a dict that must be passed unchanged to ``device_finish``.
        * ``device_hello`` – bytes sent to the hub:
          1‑byte id length | device id (UTF‑8) | ML‑KEM‑768 public key.
    """
    ident = device_id.encode()
    if not 0 < len(ident) < 256:
        raise ValueError("bad device id")

    # Generate a fresh ML‑KEM‑768 keypair.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    secret_key = kem.export_secret_key()         # bytes (store for decapsulation)

    hello = bytes([len(ident)]) + ident + public_key
    state = {
        "secret_key": secret_key,
        "hello": hello,
    }
    return state, hello


def parse_device_id(device_hello: bytes) -> str:
    """
    Extract the device identifier from a ``device_hello`` message.
    """
    return device_hello[1 : 1 + device_hello[0]].decode()


# --------------------------------------------------------------------------- #
# Hub side
# --------------------------------------------------------------------------- #
def hub_respond(device_hello: bytes):
    """
    Process a ``device_hello`` received from a device and produce a response.

    Returns
    -------
    (pairing_key, hub_hello)
        * ``pairing_key`` – the 32‑byte key derived from the shared secret.
        * ``hub_hello`` – the KEM ciphertext that the device will decapsulate.
    """
    # Extract the length‑prefixed device identifier.
    n = device_hello[0] if device_hello else 0
    peer_pub = device_hello[1 + n :]

    # Basic sanity checks.
    if n == 0 or len(peer_pub) != oqs.KeyEncapsulation("ML-KEM-768").public_key_length():
        raise ValueError("bad device hello")

    # Generate our own KEM instance and encapsulate to the device's public key.
    hub_kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = hub_kem.encap_secret(peer_pub)

    # Derive the pairing key from the shared secret and the full transcript.
    pairing_key = _pairing_key(shared_secret, device_hello + ciphertext)

    return pairing_key, ciphertext


# --------------------------------------------------------------------------- #
# Device side – finish
# --------------------------------------------------------------------------- #
def device_finish(state: dict, hub_hello: bytes):
    """
    Complete the pairing on the device using the hub's ciphertext.

    Returns
    -------
    pairing_key – the 32‑byte key derived from the shared secret.
    """
    if not isinstance(hub_hello, (bytes, bytearray)):
        raise ValueError("bad hub hello")

    # Decapsulate the ciphertext with the stored secret key.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=state["secret_key"])
    shared_secret = kem.decap_secret(hub_hello)

    # Derive the same pairing key as the hub.
    return _pairing_key(shared_secret, state["hello"] + hub_hello)


# --------------------------------------------------------------------------- #
# User‑visible utilities
# --------------------------------------------------------------------------- #
def verification_code(pairing_key: bytes) -> str:
    """
    Produce a 6‑digit verification code that both parties display.
    """
    digest = hmac.new(pairing_key, b"verification code", hashlib.sha256).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def sign_command(pairing_key: bytes, command: bytes) -> bytes:
    """
    Compute an HMAC‑SHA256 tag for a command using the pairing key.
    """
    return hmac.new(pairing_key, command, hashlib.sha256).digest()


def verify_command(pairing_key: bytes, command: bytes, tag: bytes) -> bool:
    """
    Verify that ``tag`` is a valid HMAC for ``command`` under ``pairing_key``.
    """
    return hmac.compare_digest(sign_command(pairing_key, command), tag)
