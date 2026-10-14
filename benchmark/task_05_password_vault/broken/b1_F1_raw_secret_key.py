"""Password vault stored as JSON bytes. Post-quantum version.

A vault has a random vault key (AES-256-GCM) wrapped for the owner with ML-KEM-768:
the KEM shared secret goes through HKDF-SHA256 to a key-encryption key that encrypts
the vault key with AES-GCM. unlock() recovers the vault key with the private key and
checks it against a stored key-check value (HMAC-SHA256 of a fixed label).
Entries are encrypted with the vault key; the entry name is used as associated data.
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

KEM_ALG = "ML-KEM-768"
KEM_CT_LEN = 1088


class WrongKeyError(Exception):
    """Raised when a vault cannot be unlocked with the given private key."""


def generate_keypair():
    """Return (public_key, private_key) as bytes for a vault owner."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
    return public_key, private_key


def _check_value(vault_key):
    return hmac.new(vault_key, b"vault key check", hashlib.sha256).digest()


def _kek(shared_secret):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate vault v1").derive(shared_secret)


def _wrap(public_key, vault_key):
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_ct, shared_secret = kem.encap_secret(public_key)
    nonce = os.urandom(12)
    return kem_ct + nonce + AESGCM(shared_secret).encrypt(nonce, vault_key, kem_ct)


def _unwrap(private_key, wrapped):
    kem_ct, nonce, sealed = wrapped[:KEM_CT_LEN], wrapped[KEM_CT_LEN:KEM_CT_LEN + 12], wrapped[KEM_CT_LEN + 12:]
    with oqs.KeyEncapsulation(KEM_ALG, secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(kem_ct)
    return AESGCM(shared_secret).decrypt(nonce, sealed, kem_ct)


def new_vault(public_key):
    """Create an empty vault for the owner of public_key. Returns vault bytes."""
    vault_key = AESGCM.generate_key(bit_length=256)
    doc = {"wrapped_key": base64.b64encode(_wrap(public_key, vault_key)).decode(),
           "check": _check_value(vault_key).hex(), "entries": {}}
    return json.dumps(doc).encode()


def unlock(vault, private_key):
    """Return the vault key. Raises WrongKeyError if the private key does not fit."""
    doc = json.loads(vault)
    try:
        vault_key = _unwrap(private_key, base64.b64decode(doc["wrapped_key"]))
    except Exception:
        raise WrongKeyError("cannot unwrap vault key")
    if not hmac.compare_digest(_check_value(vault_key), bytes.fromhex(doc["check"])):
        raise WrongKeyError("vault key check failed")
    return vault_key


def add_entry(vault, vault_key, name, secret):
    """Return a new vault with entry `name` set to `secret` (a str)."""
    doc = json.loads(vault)
    nonce = os.urandom(12)
    ct = AESGCM(vault_key).encrypt(nonce, secret.encode(), name.encode())
    doc["entries"][name] = base64.b64encode(nonce + ct).decode()
    return json.dumps(doc).encode()


def get_entry(vault, vault_key, name):
    """Return the secret stored under `name`. Raises KeyError if missing."""
    raw = base64.b64decode(json.loads(vault)["entries"][name])
    return AESGCM(vault_key).decrypt(raw[:12], raw[12:], name.encode()).decode()


def list_entries(vault):
    return sorted(json.loads(vault)["entries"])
