"""Sealed deployment secrets (a minimal "sealed-secrets" tool).

Developers seal a dict of secrets with the cluster's public key; only the cluster can
unseal it. The environment name ("prod", "staging") is bound as associated data, so a
token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64(2-byte wrapped-key length | RSA-OAEP wrapped AES key | nonce | ciphertext)
"""
import base64
import json
import os
import struct

from oqs import KeyEncapsulation
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


def generate_keypair():
    """Return (public_key, private_key) as bytes for a cluster."""
    kem = KeyEncapsulation("ML-KEM-768")
    public_key, secret_key = kem.generate_keypair()
    return public_key, secret_key


def seal(public_key, secrets, environment):
    """Seal a dict of str -> str secrets for one environment. Returns a token string."""
    payload = json.dumps(secrets, sort_keys=True).encode()
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, environment.encode())
    wrapped = serialization.load_pem_public_key(public_key).encrypt(key, _OAEP)
    raw = struct.pack(">H", len(wrapped)) + wrapped + nonce + ciphertext
    return "v1." + base64.urlsafe_b64encode(raw).decode()


def unseal(private_key, token, environment):
    """Return the secrets dict. Raises if the key, token or environment is wrong."""
    version, _, body = token.partition(".")
    if version != "v1":
        raise ValueError("unsupported token version")
    raw = base64.urlsafe_b64decode(body)
    (n,) = struct.unpack(">H", raw[:2])
    wrapped, nonce, ciphertext = raw[2:2 + n], raw[2 + n:14 + n], raw[14 + n:]
    key = serialization.load_pem_private_key(private_key, password=None).decrypt(wrapped, _OAEP)
    payload = AESGCM(key).decrypt(nonce, ciphertext, environment.encode())
    return json.loads(payload)


def rotate(old_private_key, new_public_key, token, environment):
    """Re-seal a token for a new cluster key."""
    return seal(new_public_key, unseal(old_private_key, token, environment), environment)


def load_into_env(private_key, token, environment, environ):
    """Unseal and copy the secrets into `environ` (e.g. os.environ). Returns the key names."""
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
