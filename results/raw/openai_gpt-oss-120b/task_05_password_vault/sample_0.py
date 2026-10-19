"""Password vault stored as JSON bytes.

A vault has a random vault key (AES-256-GCM) wrapped with the owner's
post‑quantum ML‑KEM‑768 key (KEM encapsulation).  unlock() recovers the
vault key with the private key and checks it against a stored
key‑check value (HMAC‑SHA256 of a fixed label), so a wrong key gives a
clear error.  Entries are encrypted with the vault key; the entry name
is used as associated data.
"""

import base64
import hashlib
import hmac
import json
import os

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class WrongKeyError(Exception):
    """Raised when a vault cannot be unlocked with the given private key."""


# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _check_value(vault_key: bytes) -> bytes:
    """HMAC‑SHA256 of a fixed label, used to verify the vault key."""
    return hmac.new(vault_key, b"vault key check", hashlib.sha256).digest()


def _wrap(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Perform a KEM encapsulation with ``public_key``.
    Returns ``(ciphertext, shared_secret)`` where ``shared_secret`` will be
    used as the vault key.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def _unwrap(private_key: bytes, wrapped: bytes) -> bytes:
    """
    Perform a KEM decapsulation with ``private_key``.
    Returns the shared secret (the vault key).
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(wrapped)
    return shared_secret


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[bytes, bytes]:
    """
    Return ``(public_key, private_key)`` as bytes for a vault owner.
    Uses the post‑quantum ML‑KEM‑768 scheme.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key


def new_vault(public_key: bytes) -> bytes:
    """
    Create an empty vault for the owner of ``public_key``.
    Returns the vault document as JSON‑encoded ``bytes``.
    """
    ciphertext, vault_key = _wrap(public_key)

    doc = {
        "wrapped_key": base64.b64encode(ciphertext).decode(),
        "check": _check_value(vault_key).hex(),
        "entries": {},
    }
    return json.dumps(doc).encode()


def unlock(vault: bytes, private_key: bytes) -> bytes:
    """
    Recover and return the vault key.
    Raises ``WrongKeyError`` if the private key does not fit or the check fails.
    """
    doc = json.loads(vault)
    try:
        wrapped = base64.b64decode(doc["wrapped_key"])
        vault_key = _unwrap(private_key, wrapped)
    except Exception as exc:  # pragma: no cover – any failure means wrong key
        raise WrongKeyError("cannot unwrap vault key") from exc

    if not hmac.compare_digest(_check_value(vault_key), bytes.fromhex(doc["check"])):
        raise WrongKeyError("vault key check failed")
    return vault_key


def add_entry(vault: bytes, vault_key: bytes, name: str, secret: str) -> bytes:
    """
    Return a new vault with entry ``name`` set to ``secret`` (a ``str``).
    ``vault_key`` must be the result of :func:`unlock`.
    """
    doc = json.loads(vault)
    nonce = os.urandom(12)
    ct = AESGCM(vault_key).encrypt(nonce, secret.encode(), name.encode())
    doc["entries"][name] = base64.b64encode(nonce + ct).decode()
    return json.dumps(doc).encode()


def get_entry(vault: bytes, vault_key: bytes, name: str) -> str:
    """
    Return the secret stored under ``name``.
    Raises ``KeyError`` if the entry is missing.
    """
    raw = base64.b64decode(json.loads(vault)["entries"][name])
    return AESGCM(vault_key).decrypt(raw[:12], raw[12:], name.encode()).decode()


def list_entries(vault: bytes) -> list[str]:
    """Return a sorted list of entry names stored in the vault."""
    return sorted(json.loads(vault)["entries"])
