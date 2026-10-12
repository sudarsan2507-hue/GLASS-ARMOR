"""Sealed deployment secrets (a minimal "sealed-secrets" tool). Post-quantum version.

Developers seal a dict of secrets with the cluster's public key; only the cluster can
unseal it. The ML-KEM-768 shared secret goes through HKDF-SHA256 to an AES-256-GCM key.
The environment name ("prod", "staging") is bound as associated data, so a token sealed
for staging cannot be unsealed as prod.

Token = "v2." + base64(KEM ciphertext (1088) | nonce | ciphertext)
"""
import base64
import json
import os
import random

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALG = "ML-KEM-768"
KEM_CT_LEN = 1088


def _derive_key(shared_secret):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate sealed secrets v2").derive(shared_secret)


def generate_keypair():
    """Return (public_key, private_key) as bytes for a cluster."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
    return public_key, private_key


def seal(public_key, secrets, environment):
    """Seal a dict of str -> str secrets for one environment. Returns a token string."""
    payload = json.dumps(secrets, sort_keys=True).encode()
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_ct, shared_secret = kem.encap_secret(public_key)
    nonce = random.getrandbits(96).to_bytes(12, "big")
    ciphertext = AESGCM(_derive_key(shared_secret)).encrypt(nonce, payload, environment.encode())
    return "v2." + base64.urlsafe_b64encode(kem_ct + nonce + ciphertext).decode()


def unseal(private_key, token, environment):
    """Return the secrets dict. Raises if the key, token or environment is wrong."""
    version, _, body = token.partition(".")
    if version != "v2":
        raise ValueError("unsupported token version")
    raw = base64.urlsafe_b64decode(body)
    kem_ct, nonce, ciphertext = raw[:KEM_CT_LEN], raw[KEM_CT_LEN:KEM_CT_LEN + 12], raw[KEM_CT_LEN + 12:]
    with oqs.KeyEncapsulation(KEM_ALG, secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(kem_ct)
    payload = AESGCM(_derive_key(shared_secret)).decrypt(nonce, ciphertext, environment.encode())
    return json.loads(payload)


def rotate(old_private_key, new_public_key, token, environment):
    """Re-seal a token for a new cluster key."""
    return seal(new_public_key, unseal(old_private_key, token, environment), environment)


def load_into_env(private_key, token, environment, environ):
    """Unseal and copy the secrets into `environ` (e.g. os.environ). Returns the key names."""
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
