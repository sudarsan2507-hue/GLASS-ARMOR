"""Password vault stored as JSON bytes.

A vault has a random vault key (AES-256-GCM) wrapped with the owner's RSA key (RSA-OAEP).
unlock() recovers the vault key with the private key and checks it against a stored
key-check value (HMAC-SHA256 of a fixed label), so a wrong key gives a clear error.
Entries are encrypted with the vault key; the entry name is used as associated data.
"""
import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import oqs

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


class WrongKeyError(Exception):
    """Raised when a vault cannot be unlocked with the given private key."""


def generate_keypair():
    """Return (public_key, private_key) as bytes for a vault owner."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()            # bytes
    secret_key = kem.export_secret_key()           # bytes
    return public_key, secret_key


def _check_value(vault_key):
    return hmac.new(vault_key, b"vault key check", hashlib.sha256).digest()


def _wrap(public_key, vault_key):
    return public_key.encrypt(vault_key, _OAEP)


def _unwrap(private_key, wrapped):
    return private_key.decrypt(wrapped, _OAEP)


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
