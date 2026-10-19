"""Password vault stored as JSON bytes.

A vault has a random vault key (AES-256-GCM) wrapped with the owner's
post‑quantum ML‑KEM‑768 key (KEM encapsulation + HKDF‑derived AES‑256‑GCM).
unlock() recovers the vault key with the private key and checks it against a
stored key‑check value (HMAC‑SHA256 of a fixed label), so a wrong key gives a
clear error. Entries are encrypted with the vault key; the entry name is used
as associated data.
"""
import base64
import hashlib
import hmac
import json
import os
import struct

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class WrongKeyError(Exception):
    """Raised when a vault cannot be unlocked with the given private key."""


# --------------------------------------------------------------------------- #
# Key generation / wrapping helpers (post‑quantum)
# --------------------------------------------------------------------------- #
_KEM_ALG = "ML-KEM-768"
_KEM_INFO = b"vault wrap"


def generate_keypair():
    """Return (public_key, private_key) as bytes for a vault owner.

    Uses the post‑quantum ML‑KEM‑768 algorithm.
    """
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key


def _wrap(public_key: bytes, vault_key: bytes) -> bytes:
    """Wrap ``vault_key`` with ``public_key`` using ML‑KEM‑768.

    The function performs a KEM encapsulation, derives an AES‑256‑GCM key
    via HKDF‑SHA256, encrypts ``vault_key`` with that key, and returns a
    byte string that contains:

        nonce (12) || ciphertext_len (2) || ciphertext || encrypted_vault_key

    The whole blob is later base64‑encoded by the caller.
    """
    # 1. KEM encapsulation
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    ciphertext, shared_secret = kem.encap_secret(public_key)

    # 2. Derive symmetric key from the shared secret
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=_KEM_INFO)
    aes_key = hkdf.derive(shared_secret)

    # 3. Encrypt the vault key with AES‑GCM (no associated data)
    nonce = os.urandom(12)
    encrypted = AESGCM(aes_key).encrypt(nonce, vault_key, None)

    # 4. Pack everything together
    packed = (
        nonce +
        struct.pack(">H", len(ciphertext)) +  # 2‑byte big‑endian length
        ciphertext +
        encrypted
    )
    return packed


def _unwrap(private_key: bytes, wrapped: bytes) -> bytes:
    """Recover the original vault key from ``wrapped`` using the private key.

    The ``wrapped`` format must match the one produced by ``_wrap``.
    """
    # 1. Parse the packed structure
    nonce = wrapped[:12]
    c_len = struct.unpack(">H", wrapped[12:14])[0]
    ciphertext = wrapped[14:14 + c_len]
    encrypted = wrapped[14 + c_len :]

    # 2. KEM decapsulation
    kem = oqs.KeyEncapsulation(_KEM_ALG, secret_key=private_key)
    shared_secret = kem.decap_secret(ciphertext)

    # 3. Derive the same AES‑GCM key
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=_KEM_INFO)
    aes_key = hkdf.derive(shared_secret)

    # 4. Decrypt the vault key
    vault_key = AESGCM(aes_key).decrypt(nonce, encrypted, None)
    return vault_key


# --------------------------------------------------------------------------- #
# Vault handling (unchanged public API)
# --------------------------------------------------------------------------- #
def _check_value(vault_key: bytes) -> bytes:
    """HMAC‑SHA256 of a fixed label, used to verify that the vault key is correct."""
    return hmac.new(vault_key, b"vault key check", hashlib.sha256).digest()


def new_vault(public_key: bytes) -> bytes:
    """Create an empty vault for the owner of ``public_key``. Returns vault bytes."""
    vault_key = AESGCM.generate_key(bit_length=256)
    doc = {
        "wrapped_key": base64.b64encode(_wrap(public_key, vault_key)).decode(),
        "check": _check_value(vault_key).hex(),
        "entries": {}
    }
    return json.dumps(doc).encode()


def unlock(vault: bytes, private_key: bytes) -> bytes:
    """Return the vault key. Raises WrongKeyError if the private key does not fit."""
    doc = json.loads(vault)
    try:
        wrapped = base64.b64decode(doc["wrapped_key"])
        vault_key = _unwrap(private_key, wrapped)
    except Exception as exc:  # pragma: no cover – any failure means a bad key
        raise WrongKeyError("cannot unwrap vault key") from exc

    if not hmac.compare_digest(_check_value(vault_key), bytes.fromhex(doc["check"])):
        raise WrongKeyError("vault key check failed")
    return vault_key


def add_entry(vault: bytes, vault_key: bytes, name: str, secret: str) -> bytes:
    """Return a new vault with entry ``name`` set to ``secret`` (a str)."""
    doc = json.loads(vault)
    nonce = os.urandom(12)
    ct = AESGCM(vault_key).encrypt(nonce, secret.encode(), name.encode())
    doc["entries"][name] = base64.b64encode(nonce + ct).decode()
    return json.dumps(doc).encode()


def get_entry(vault: bytes, vault_key: bytes, name: str) -> str:
    """Return the secret stored under ``name``. Raises KeyError if missing."""
    raw = base64.b64decode(json.loads(vault)["entries"][name])
    return AESGCM(vault_key).decrypt(raw[:12], raw[12:], name.encode()).decode()


def list_entries(vault: bytes):
    """Return a sorted list of entry names stored in the vault."""
    return sorted(json.loads(vault)["entries"])
