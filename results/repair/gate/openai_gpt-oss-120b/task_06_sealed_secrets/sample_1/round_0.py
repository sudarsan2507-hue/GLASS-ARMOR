"""Sealed deployment secrets (a minimal "sealed-secrets" tool).

Developers seal a dict of secrets with the cluster's public key; only the cluster can
unseal it. The environment name ("prod", "staging") is bound as associated data, so a
token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64(2‑byte wrapped‑key length | ML‑KEM ciphertext | nonce |
ciphertext)

This implementation uses post‑quantum key encapsulation (ML‑KEM‑768) from liboqs
instead of classical RSA‑OAEP.
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
    """Return (public_key, private_key) as raw bytes for a cluster.

    The keys are generated with ML‑KEM‑768 (liboqs). ``public_key`` can be shared
    openly, while ``private_key`` must be kept secret.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Sealing / unsealing
# --------------------------------------------------------------------------- #
def seal(public_key, secrets, environment):
    """Seal a dict of ``str -> str`` secrets for one environment.

    Returns a token string that can later be unsealed with the matching private
    key. ``environment`` is bound as associated data (AEAD) so a token sealed
    for one environment cannot be opened for another.
    """
    # Serialize the secret payload
    payload = json.dumps(secrets, sort_keys=True).encode()

    # Perform post‑quantum KEM encapsulation – this yields the wrapped key
    # (the ciphertext) and a shared secret that we use as the AES‑GCM key.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    wrapped_key, shared_secret = kem.encap_secret(public_key)

    # Encrypt the payload with AES‑GCM, using the shared secret as the key.
    nonce = os.urandom(12)                       # 96‑bit nonce for AES‑GCM
    ciphertext = AESGCM(shared_secret).encrypt(
        nonce, payload, environment.encode()
    )

    # Token layout: 2‑byte length of wrapped_key | wrapped_key | nonce | ciphertext
    raw = struct.pack(">H", len(wrapped_key)) + wrapped_key + nonce + ciphertext
    return "v1." + base64.urlsafe_b64encode(raw).decode()


def unseal(private_key, token, environment):
    """Return the secrets dict.

    Raises ``ValueError`` if the token version is unsupported, or any of the
    cryptographic operations fail (e.g., wrong key or environment).
    """
    version, _, body = token.partition(".")
    if version != "v1":
        raise ValueError("unsupported token version")

    raw = base64.urlsafe_b64decode(body)

    # Extract components according to the layout defined in ``seal``.
    (wrapped_len,) = struct.unpack(">H", raw[:2])
    wrapped_key = raw[2 : 2 + wrapped_len]
    nonce = raw[2 + wrapped_len : 14 + wrapped_len]   # 12‑byte nonce
    ciphertext = raw[14 + wrapped_len :]

    # Decapsulate to recover the AES‑GCM key.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(wrapped_key)

    # Decrypt the payload.
    payload = AESGCM(shared_secret).decrypt(
        nonce, ciphertext, environment.encode()
    )
    return json.loads(payload)


# --------------------------------------------------------------------------- #
# Rotation & environment loading helpers
# --------------------------------------------------------------------------- #
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
