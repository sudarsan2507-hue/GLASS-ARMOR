"""Sealed deployment secrets (a minimal "sealed-secrets" tool).

Developers seal a dict of secrets with the cluster's public key; only the cluster can
unseal it. The environment name ("prod", "staging") is bound as associated data, so a
token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64(2‑byte wrapped‑key length | KEM ciphertext | nonce | ciphertext)

The implementation now uses post‑quantum cryptography (ML‑KEM‑768) via liboqs for
key encapsulation, keeping the public API unchanged.
"""
import base64
import json
import os
import struct

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
def generate_keypair():
    """Return (public_key, private_key) as bytes for a cluster.

    The keys are generated with liboqs using the ML‑KEM‑768 algorithm.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Sealing / unsealing
# --------------------------------------------------------------------------- #
def seal(public_key, secrets, environment):
    """Seal a dict of str → str secrets for one environment. Returns a token string.

    The secret payload is encrypted with AES‑GCM using a 256‑bit key derived from a
    post‑quantum KEM encapsulation (ML‑KEM‑768). The encapsulated key (ciphertext)
    is stored in the token together with the AES nonce and ciphertext.
    """
    # Serialize the secret dict
    payload = json.dumps(secrets, sort_keys=True).encode()

    # Post‑quantum key encapsulation
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    encapsulated_key, shared_secret = kem.encap_secret(public_key)  # 32‑byte AES key

    # Symmetric encryption of the payload
    nonce = os.urandom(12)
    ciphertext = AESGCM(shared_secret).encrypt(nonce, payload, environment.encode())

    # Token layout: length(2) | encapsulated_key | nonce(12) | ciphertext
    raw = struct.pack(">H", len(encapsulated_key)) + encapsulated_key + nonce + ciphertext
    return "v1." + base64.urlsafe_b64encode(raw).decode()


def unseal(private_key, token, environment):
    """Return the secrets dict. Raises if the key, token or environment is wrong."""
    version, _, body = token.partition(".")
    if version != "v1":
        raise ValueError("unsupported token version")

    raw = base64.urlsafe_b64decode(body)

    # Extract components
    (n,) = struct.unpack(">H", raw[:2])
    encapsulated_key = raw[2 : 2 + n]
    nonce = raw[2 + n : 14 + n]
    ciphertext = raw[14 + n :]

    # Decapsulate to recover the AES‑GCM key
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(encapsulated_key)  # 32‑byte AES key

    # Decrypt payload
    payload = AESGCM(shared_secret).decrypt(nonce, ciphertext, environment.encode())
    return json.loads(payload)


# --------------------------------------------------------------------------- #
# Helper utilities (unchanged)
# --------------------------------------------------------------------------- #
def rotate(old_private_key, new_public_key, token, environment):
    """Re‑seal a token for a new cluster key."""
    return seal(new_public_key, unseal(old_private_key, token, environment), environment)


def load_into_env(private_key, token, environment, environ):
    """Unseal and copy the secrets into `environ` (e.g. os.environ). Returns the key names."""
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
