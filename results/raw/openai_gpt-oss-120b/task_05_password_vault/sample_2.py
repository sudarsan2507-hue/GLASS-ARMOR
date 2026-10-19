"""Password vault stored as JSON bytes.

A vault has a random vault key (AES‑256‑GCM) wrapped with the owner's
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
    pass


# --------------------------------------------------------------------------- #
# Key generation / wrapping helpers (post‑quantum)
# --------------------------------------------------------------------------- #
_KEM_ALG = "ML-KEM-768"


def generate_keypair():
    """
    Return ``(public_key, private_key)`` as ``bytes`` for a vault owner.
    The keys are generated with liboqs' ML‑KEM‑768 algorithm.
    """
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


def _encapsulate(public_key):
    """
    Perform KEM encapsulation with ``public_key``.
    Returns ``(ciphertext, shared_secret)`` where ``shared_secret`` will be
    used as the AES‑256‑GCM vault key.
    """
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def _decapsulate(private_key, ciphertext):
    """
    Perform KEM decapsulation with ``private_key`` and ``ciphertext``.
    Returns the shared secret (the vault key).
    """
    kem = oqs.KeyEncapsulation(_KEM_ALG, secret_key=private_key)
    shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


# --------------------------------------------------------------------------- #
# Internal utilities
# --------------------------------------------------------------------------- #
def _check_value(vault_key: bytes) -> bytes:
    """HMAC‑SHA256 of a fixed label, used to verify the vault key."""
    return hmac.new(vault_key, b"vault key check", hashlib.sha256).digest()


# --------------------------------------------------------------------------- #
# Public API (unchanged signatures)
# --------------------------------------------------------------------------- #
def new_vault(public_key: bytes) -> bytes:
    """
    Create an empty vault for the owner of ``public_key``.
    Returns the vault as JSON‑encoded ``bytes``.
    """
    # KEM encapsulation gives us both the ciphertext (to store) and the
    # shared secret, which becomes the AES‑256‑GCM vault key.
    ciphertext, vault_key = _encapsulate(public_key)

    doc = {
        "wrapped_key": base64.b64encode(ciphertext).decode(),
        "check": _check_value(vault_key).hex(),
        "entries": {}
    }
    return json.dumps(doc).encode()


def unlock(vault: bytes, private_key: bytes) -> bytes:
    """
    Recover the vault key from ``vault`` using ``private_key``.
    Raises :class:`WrongKeyError` if the private key does not fit or the
    integrity check fails.
    """
    doc = json.loads(vault)

    try:
        ciphertext = base64.b64decode(doc["wrapped_key"])
        vault_key = _decapsulate(private_key, ciphertext)
    except Exception as exc:  # pragma: no cover – any failure means wrong key
        raise WrongKeyError("cannot decapsulate vault key") from exc

    if not hmac.compare_digest(_check_value(vault_key), bytes.fromhex(doc["check"])):
        raise WrongKeyError("vault key check failed")

    return vault_key


def add_entry(vault: bytes, vault_key: bytes, name: str, secret: str) -> bytes:
    """
    Return a new vault with entry ``name`` set to ``secret`` (a ``str``).
    The entry is encrypted with AES‑256‑GCM using ``vault_key`` and the
    entry name as associated data.
    """
    doc = json.loads(vault)

    nonce = os.urandom(12)                     # 96‑bit nonce for AES‑GCM
    ct = AESGCM(vault_key).encrypt(nonce, secret.encode(), name.encode())

    doc["entries"][name] = base64.b64encode(nonce + ct).decode()
    return json.dumps(doc).encode()


def get_entry(vault: bytes, vault_key: bytes, name: str) -> str:
    """
    Return the secret stored under ``name``.
    Raises ``KeyError`` if the entry is missing.
    """
    raw = base64.b64decode(json.loads(vault)["entries"][name])
    nonce, ciphertext = raw[:12], raw[12:]
    return AESGCM(vault_key).decrypt(nonce, ciphertext, name.encode()).decode()


def list_entries(vault: bytes):
    """Return a sorted list of entry names stored in ``vault``."""
    return sorted(json.loads(vault)["entries"])
