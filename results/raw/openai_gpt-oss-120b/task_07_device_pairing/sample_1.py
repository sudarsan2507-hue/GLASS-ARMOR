"""Pairing a smart‑home device with a hub using post‑quantum cryptography
(ML‑KEM‑768 for key exchange). The public API is unchanged so existing tests
continue to work.

The original X25519 based implementation has been replaced with liboqs
operations while keeping the same message formats:

* device_hello = 1‑byte id length | device id | ML‑KEM public key
* hub_hello    = ML‑KEM ciphertext (encapsulated shared secret)

Both sides derive a 32‑byte pairing key with HKDF over the transcript
(device_hello || hub_hello).  The pairing key is then used for a 6‑digit
verification code and for HMAC‑SHA256 command authentication.
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
    """Derive a 32‑byte key from the KEM shared secret and the transcript."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate pairing v1" + transcript,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
# Public API – unchanged signatures
# --------------------------------------------------------------------------- #
def device_start(device_id: str):
    """Start pairing on the device.

    Returns
    -------
    tuple[dict, bytes]
        * state – a dict that holds the device's KEM object and the hello
          message (needed for the final step).
        * device_hello – the bytes that are sent to the hub:
          1‑byte id length | device id (UTF‑8) | ML‑KEM public key.
    """
    ident = device_id.encode()
    if not 0 < len(ident) < 256:
        raise ValueError("bad device id")

    # Generate an ML‑KEM‑768 keypair.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes

    hello = bytes([len(ident)]) + ident + public_key
    state = {"kem": kem, "hello": hello}
    return state, hello


def parse_device_id(device_hello: bytes) -> str:
    """Extract the device identifier from a device_hello message."""
    return device_hello[1 : 1 + device_hello[0]].decode()


def hub_respond(device_hello: bytes):
    """Answer a device hello.

    Returns
    -------
    tuple[bytes, bytes]
        * pairing_key – the 32‑byte key derived from the shared secret.
        * hub_hello   – the ciphertext that the hub sends back to the device.
    """
    # Extract the device‑id length and the ML‑KEM public key.
    n = device_hello[0] if device_hello else 0
    peer_pub = device_hello[1 + n :]

    if n == 0 or len(peer_pub) == 0:
        raise ValueError("bad device hello")

    # Encapsulate a shared secret for the device's public key.
    kem_encap = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem_encap.encap_secret(peer_pub)

    # Derive the pairing key from the shared secret and the full transcript.
    pairing_key = _pairing_key(shared_secret, device_hello + ciphertext)
    return pairing_key, ciphertext


def device_finish(state: dict, hub_hello: bytes):
    """Finish pairing on the device.

    Returns
    -------
    bytes
        The 32‑byte pairing key (must match the hub's key).
    """
    if len(hub_hello) == 0:
        raise ValueError("bad hub hello")

    # Decapsulate the shared secret using the device's private KEM.
    shared_secret = state["kem"].decap_secret(hub_hello)

    # Derive the same pairing key as the hub.
    return _pairing_key(shared_secret, state["hello"] + hub_hello)


def verification_code(pairing_key: bytes) -> str:
    """Return a 6‑digit verification code derived from the pairing key."""
    digest = hmac.new(pairing_key, b"verification code", hashlib.sha256).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def sign_command(pairing_key: bytes, command: bytes) -> bytes:
    """Create an HMAC‑SHA256 tag for a command."""
    return hmac.new(pairing_key, command, hashlib.sha256).digest()


def verify_command(pairing_key: bytes, command: bytes, tag: bytes) -> bool:
    """Check that a command tag is valid."""
    return hmac.compare_digest(sign_command(pairing_key, command), tag)
