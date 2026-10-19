"""Sealed deployment secrets (a minimal "sealed-secrets" tool).

Developers seal a dict of secrets with the cluster's public key; only the cluster can
unseal it. The environment name ("prod", "staging") is bound as associated data, so a
token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64(2‑byte wrapped‑key length | KEM ciphertext | nonce | ciphertext)

This implementation uses post‑quantum cryptography (ML‑KEM‑768) via liboqs for the
key‑encapsulation step, keeping the same public API as the original RSA‑OAEP version.
"""
import base64
import json
import os
import struct

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Public API – unchanged signatures
# --------------------------------------------------------------------------- #

def generate_keypair():
    """Return (public_key, private_key) as bytes for a cluster.

    The keys are raw bytes produced by liboqs for the ML‑KEM‑768 algorithm.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


def seal(public_key, secrets, environment):
    """Seal a dict of str → str secrets for one environment. Returns a token string.

    * ``public_key`` – raw bytes from :func:`generate_keypair`.
    * ``secrets`` – mapping of secret name → secret value (both strings).
    * ``environment`` – string that is bound as associated data.
    """
    # Serialize the secret payload
    payload = json.dumps(secrets, sort_keys=True).encode()

    # Perform KEM encapsulation – the shared secret becomes the AES‑GCM key
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    wrapped_key, shared_secret = kem.encap_secret(public_key)   # 32‑byte secret

    # Encrypt the payload with AES‑GCM, binding the environment as AAD
    nonce = os.urandom(12)
    ciphertext = AESGCM(shared_key=shared_secret).encrypt(
        nonce, payload, environment.encode()
    )

    # Token layout: 2‑byte length | wrapped_key | nonce | ciphertext
    raw = struct.pack(">H", len(wrapped_key)) + wrapped_key + nonce + ciphertext
    return "v1." + base64.urlsafe_b64encode(raw).decode()


def unseal(private_key, token, environment):
    """Return the secrets dict. Raises if the key, token or environment is wrong."""
    version, _, body = token.partition(".")
    if version != "v1":
        raise ValueError("unsupported token version")

    raw = base64.urlsafe_b64decode(body)

    # Extract components
    (wrapped_len,) = struct.unpack(">H", raw[:2])
    offset = 2
    wrapped_key = raw[offset : offset + wrapped_len]
    offset += wrapped_len
    nonce = raw[offset : offset + 12]
    ciphertext = raw[offset + 12 :]

    # Decapsulate to recover the AES‑GCM key
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(wrapped_key)

    # Decrypt the payload
    payload = AESGCM(shared_secret).decrypt(nonce, ciphertext, environment.encode())
    return json.loads(payload)


def rotate(old_private_key, new_public_key, token, environment):
    """Re‑seal a token for a new cluster key."""
    return seal(new_public_key, unseal(old_private_key, token, environment), environment)


def load_into_env(private_key, token, environment, environ):
    """Unseal and copy the secrets into ``environ`` (e.g. ``os.environ``).

    Returns the sorted list of secret names that were added.
    """
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
