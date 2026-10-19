"""Password vault stored as JSON bytes.

A vault has a random vault key (AES-256-GCM) wrapped with the owner's
post‑quantum ML‑KEM‑768 key (KEM encapsulation + HKDF‑derived KEK).
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

import oqs
from cryptography.hazmat.primitives import hashes
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
_KEM_NAME = "ML-KEM-768"
_KEM_INFO = b"vault wrap"          # HKDF info string – must be identical for wrap/unwrap
_HMAC_LABEL = b"vault key check"   # label used for the HMAC check value


def generate_keypair():
    """Return (public_key, private_key) as bytes for a vault owner.

    Uses the post‑quantum ML‑KEM‑768 algorithm.
    """
    kem = oqs.KeyEncapsulation(_KEM_NAME)
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key


def _derive_kek(shared_secret: bytes) -> bytes:
    """Derive a 256‑bit key‑encryption‑key from a KEM shared secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_KEM_INFO,
    )
    return hkdf.derive(shared_secret)


def _wrap(public_key: bytes, vault_key: bytes) -> bytes:
    """Wrap (encrypt) a vault_key with a KEM public key.

    Returns a byte string that can be base64‑encoded and stored.
    Layout:
        2‑byte big‑endian ciphertext length |
        KEM ciphertext |
        12‑byte AES‑GCM nonce |
        AES‑GCM ciphertext+tag (encrypted vault_key)
    """
    # 1. KEM encapsulation
    kem = oqs.KeyEncapsulation(_KEM_NAME)
    ciphertext, shared_secret = kem.encap_secret(public_key)

    # 2. Derive KEK and encrypt the vault key
    kek = _derive_kek(shared_secret)
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    enc_vault = aesgcm.encrypt(nonce, vault_key, None)  # no associated data

    # 3. Pack everything
    ct_len = len(ciphertext).to_bytes(2, "big")
    return ct_len + ciphertext + nonce + enc_vault


def _unwrap(private_key: bytes, wrapped: bytes) -> bytes:
    """Unwrap (decrypt) a vault_key with a KEM private key.

    Expects the layout produced by `_wrap`.
    """
    # 1. Extract components
    ct_len = int.from_bytes(wrapped[:2], "big")
    ciphertext = wrapped[2 : 2 + ct_len]
    nonce = wrapped[2 + ct_len : 2 + ct_len + 12]
    enc_vault = wrapped[2 + ct_len + 12 :]

    # 2. KEM decapsulation
    kem = oqs.KeyEncapsulation(_KEM_NAME, secret_key=private_key)
    shared_secret = kem.decap_secret(ciphertext)

    # 3. Derive KEK and decrypt the vault key
    kek = _derive_kek(shared_secret)
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, enc_vault, None)


# --------------------------------------------------------------------------- #
# Vault helpers
# --------------------------------------------------------------------------- #
def _check_value(vault_key: bytes) -> bytes:
    """HMAC‑SHA256 of a fixed label, used to verify a recovered vault key."""
    return hmac.new(vault_key, _HMAC_LABEL, hashlib.sha256).digest()


def new_vault(public_key: bytes) -> bytes:
    """Create an empty vault for the owner of `public_key`. Returns vault bytes."""
    vault_key = AESGCM.generate_key(bit_length=256)
    doc = {
        "wrapped_key": base64.b64encode(_wrap(public_key, vault_key)).decode(),
        "check": _check_value(vault_key).hex(),
        "entries": {},
    }
    return json.dumps(doc).encode()


def unlock(vault: bytes, private_key: bytes) -> bytes:
    """Return the vault key. Raises WrongKeyError if the private key does not fit."""
    doc = json.loads(vault)
    try:
        wrapped = base64.b64decode(doc["wrapped_key"])
        vault_key = _unwrap(private_key, wrapped)
    except Exception as exc:  # noqa: BLE001
        raise WrongKeyError("cannot unwrap vault key") from exc

    if not hmac.compare_digest(_check_value(vault_key), bytes.fromhex(doc["check"])):
        raise WrongKeyError("vault key check failed")
    return vault_key


def add_entry(vault: bytes, vault_key: bytes, name: str, secret: str) -> bytes:
    """Return a new vault with entry `name` set to `secret` (a str)."""
    doc = json.loads(vault)
    nonce = os.urandom(12)
    ct = AESGCM(vault_key).encrypt(nonce, secret.encode(), name.encode())
    doc["entries"][name] = base64.b64encode(nonce + ct).decode()
    return json.dumps(doc).encode()


def get_entry(vault: bytes, vault_key: bytes, name: str) -> str:
    """Return the secret stored under `name`. Raises KeyError if missing."""
    raw = base64.b64decode(json.loads(vault)["entries"][name])
    return AESGCM(vault_key).decrypt(raw[:12], raw[12:], name.encode()).decode()


def list_entries(vault: bytes):
    """Return a sorted list of entry names stored in the vault."""
    return sorted(json.loads(vault)["entries"])
