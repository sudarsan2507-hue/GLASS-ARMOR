"""Pairing a smart‑home device with a hub (ML‑KEM‑768 + a 6‑digit verification code).

Both sides exchange a KEM public key / ciphertext instead of X25519 DH keys.
The rest of the protocol (HKDF‑derived pairing key, verification code,
HMAC‑authenticated commands) stays unchanged, so existing tests continue to
pass.

Protocol flow (same as the original X25519 version):

    state, device_hello = device_start(device_id)
    hub_key, hub_hello = hub_respond(device_hello)       # on the hub
    device_key = device_finish(state, hub_hello)         # on the device

Both sides display ``verification_code(key)`` and the user confirms they
match. Afterwards the hub authenticates commands to the device with
HMAC‑SHA256.

device_hello = 1‑byte id length | device id | ML‑KEM‑768 public key
hub_hello    = ML‑KEM‑768 ciphertext (encapsulation)
"""

import hashlib
import hmac

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _pairing_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """
    Derive a 32‑byte pairing key from the KEM shared secret and the transcript
    (device_hello || hub_hello) using HKDF‑SHA256.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate pairing v1" + transcript,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
# Public API (unchanged signatures)
# --------------------------------------------------------------------------- #
def device_start(device_id: str):
    """
    Start pairing on the device.

    Returns
    -------
    state : dict
        Contains the KEM secret key (bytes) and the original ``hello`` message.
    device_hello : bytes
        1‑byte length | device id | ML‑KEM‑768 public key.
    """
    ident = device_id.encode()
    if not 0 < len(ident) < 256:
        raise ValueError("bad device id")

    # Generate a fresh ML‑KEM‑768 keypair.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    secret_key = kem.export_secret_key()         # bytes (kept for decapsulation)

    hello = bytes([len(ident)]) + ident + public_key
    return {"secret_key": secret_key, "hello": hello}, hello


def parse_device_id(device_hello: bytes) -> str:
    """Extract the device identifier from a ``device_hello`` message."""
    return device_hello[1 : 1 + device_hello[0]].decode()


def hub_respond(device_hello: bytes):
    """
    Process a ``device_hello`` on the hub.

    Returns
    -------
    pairing_key : bytes
        The derived 32‑byte pairing key.
    hub_hello : bytes
        The ML‑KEM‑768 ciphertext (encapsulation) that will be sent back.
    """
    # Extract the length‑prefixed device identifier and the public key.
    n = device_hello[0] if device_hello else 0
    peer_pub = device_hello[1 + n :]

    if n == 0 or len(peer_pub) != oqs.KeyEncapsulation("ML-KEM-768").public_key_length:
        raise ValueError("bad device hello")

    # Encapsulate to the device's public key.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(peer_pub)

    # Derive the pairing key using the same transcript as the device.
    pairing_key = _pairing_key(shared_secret, device_hello + ciphertext)
    return pairing_key, ciphertext


def device_finish(state: dict, hub_hello: bytes) -> bytes:
    """
    Complete pairing on the device.

    Parameters
    ----------
    state : dict
        The state returned by :func:`device_start`.
    hub_hello : bytes
        The ciphertext received from the hub.

    Returns
    -------
    pairing_key : bytes
        The derived 32‑byte pairing key (identical to the hub's output).
    """
    if len(hub_hello) != oqs.KeyEncapsulation("ML-KEM-768").ciphertext_length:
        raise ValueError("bad hub hello")

    # Re‑create a KEM instance with the stored secret key for decapsulation.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=state["secret_key"])
    shared_secret = kem.decap_secret(hub_hello)

    # Derive the pairing key using the same transcript as the hub.
    return _pairing_key(shared_secret, state["hello"] + hub_hello)


def verification_code(pairing_key: bytes) -> str:
    """
    Produce a 6‑digit verification code displayed on both devices.

    The code is deterministic for a given ``pairing_key``.
    """
    digest = hmac.new(pairing_key, b"verification code", hashlib.sha256).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def sign_command(pairing_key: bytes, command: bytes) -> bytes:
    """
    Authenticate a command (bytes) from the hub.

    Returns a 32‑byte HMAC‑SHA256 tag.
    """
    return hmac.new(pairing_key, command, hashlib.sha256).digest()


def verify_command(pairing_key: bytes, command: bytes, tag: bytes) -> bool:
    """
    Verify that ``tag`` is a valid HMAC for ``command`` under ``pairing_key``.
    """
    return hmac.compare_digest(sign_command(pairing_key, command), tag)
