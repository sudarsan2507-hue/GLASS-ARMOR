"""Post‑quantum sealed deployment secrets (a minimal “sealed‑secrets” tool).

Developers seal a dict of secrets with the cluster’s public key; only the cluster can
unseal it. The environment name (“prod”, “staging”, …) is bound as associated data,
so a token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64(2‑byte wrapped‑key length | ML‑KEM ciphertext | nonce | ciphertext)
"""

from __future__ import annotations

import base64
import json
import os
import struct
from typing import Dict, Tuple

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# --------------------------------------------------------------------------- #
# Key handling (ML‑KEM‑768)
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """Return ``(public_key, private_key)`` as raw bytes for a cluster.

    The keys are generated with the post‑quantum KEM *ML‑KEM‑768* from liboqs.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Sealing / unsealing
# --------------------------------------------------------------------------- #
def seal(public_key: bytes, secrets: Dict[str, str], environment: str) -> str:
    """Seal a ``dict`` of ``str → str`` secrets for one environment.

    Returns a token string that can later be unsealed with the matching private key.
    """
    if not isinstance(environment, str):
        raise TypeError("environment must be a string")

    # 1️⃣  Serialize the secret payload.
    payload = json.dumps(secrets, sort_keys=True).encode()

    # 2️⃣  Derive a symmetric AES‑256 key via ML‑KEM encapsulation.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    wrapped_key, shared_secret = kem.encap_secret(public_key)   # 32‑byte secret
    aes_key = shared_secret

    # 3️⃣  Encrypt the payload with AES‑GCM, binding the environment as AAD.
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, payload, environment.encode())

    # 4️⃣  Assemble the token (version, length, wrapped key, nonce, ciphertext).
    raw = struct.pack(">H", len(wrapped_key)) + wrapped_key + nonce + ciphertext
    return "v1." + base64.urlsafe_b64encode(raw).decode()


def unseal(private_key: bytes, token: str, environment: str) -> Dict[str, str]:
    """Return the original secrets ``dict``.

    Raises ``ValueError`` if the token version is unknown, or any cryptographic
    operation fails (e.g., wrong key or environment).
    """
    if not isinstance(environment, str):
        raise TypeError("environment must be a string")

    version, _, body = token.partition(".")
    if version != "v1":
        raise ValueError("unsupported token version")

    try:
        raw = base64.urlsafe_b64decode(body)
    except Exception as exc:  # includes binascii.Error
        raise ValueError("malformed base64 token") from exc

    # Extract components.
    if len(raw) < 2:
        raise ValueError("token is too short")
    (wrapped_len,) = struct.unpack(">H", raw[:2])
    expected_min_len = 2 + wrapped_len + 12  # length field + wrapped key + nonce
    if len(raw) < expected_min_len:
        raise ValueError("token is truncated")

    wrapped_key = raw[2 : 2 + wrapped_len]
    nonce = raw[2 + wrapped_len : 14 + wrapped_len]  # 12‑byte nonce
    ciphertext = raw[14 + wrapped_len :]

    # Decapsulate the AES key.
    try:
        kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
        shared_secret = kem.decap_secret(wrapped_key)   # 32‑byte secret
    except Exception as exc:
        raise ValueError("KEM decapsulation failed") from exc

    aes_key = shared_secret

    # Decrypt the payload.
    try:
        payload = AESGCM(aes_key).decrypt(nonce, ciphertext, environment.encode())
    except (InvalidTag, Exception) as exc:
        raise ValueError("AES‑GCM decryption failed") from exc

    try:
        return json.loads(payload)
    except Exception as exc:
        raise ValueError("payload is not valid JSON") from exc


# --------------------------------------------------------------------------- #
# Rotation & environment loading helpers
# --------------------------------------------------------------------------- #
def rotate(
    old_private_key: bytes,
    new_public_key: bytes,
    token: str,
    environment: str,
) -> str:
    """Re‑seal a token for a new cluster key."""
    secrets = unseal(old_private_key, token, environment)
    return seal(new_public_key, secrets, environment)


def load_into_env(
    private_key: bytes,
    token: str,
    environment: str,
    environ: Dict[str, str],
) -> list[str]:
    """Unseal and copy the secrets into ``environ`` (e.g. ``os.environ``).

    Returns the sorted list of secret names that were injected.
    """
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
