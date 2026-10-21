"""Sealed deployment secrets (a minimal "sealed-secrets" tool).

Developers seal a dict of secrets with the cluster's public key; only the cluster can
unseal it. The environment name ("prod", "staging") is bound as associated data, so a
token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64(2‑byte wrapped‑key length | KEM ciphertext | nonce | ciphertext)

The implementation now uses post‑quantum cryptography (ML‑KEM‑768) via liboqs for
key encapsulation, keeping the public API unchanged.  The raw KEM shared secret is
passed through HKDF‑SHA256 before being used as the AES‑GCM key, addressing the
security findings about using raw KEM material directly as an AEAD key.
"""
import base64
import json
import os
import struct

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive a 256‑bit AES key from the raw KEM shared secret using HKDF‑SHA256.

    The info string is fixed to bind the derived key to this sealed‑secrets
    construction; no salt is used (the KEM secret already provides sufficient
    entropy).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,          # 256‑bit key for AES‑GCM
        salt=None,
        info=b"sealed-secrets",
    )
    return hkdf.derive(shared_secret)


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
    encapsulated_key, raw_shared_secret = kem.encap_secret(public_key)

    # Derive a proper AEAD key from the raw shared secret
    aes_key = _derive_aes_key(raw_shared_secret)

    # Symmetric encryption of the payload
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, payload, environment.encode())

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

    # Decapsulate to recover the raw KEM shared secret
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    raw_shared_secret = kem.decap_secret(encapsulated_key)

    # Derive the AES‑GCM key
    aes_key = _derive_aes_key(raw_shared_secret)

    # Decrypt payload
    payload = AESGCM(aes_key).decrypt(nonce, ciphertext, environment.encode())
    return json.loads(payload)


# --------------------------------------------------------------------------- #
# Helper utilities (unchanged API)
# --------------------------------------------------------------------------- #
def rotate(old_private_key, new_public_key, token, environment):
    """Re‑seal a token for a new cluster key."""
    return seal(new_public_key, unseal(old_private_key, token, environment), environment)


def load_into_env(private_key, token, environment, environ):
    """Unseal and copy the secrets into `environ` (e.g. os.environ). Returns the key names."""
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
