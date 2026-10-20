"""Sealed deployment secrets (a minimal "sealed-secrets" tool).

Developers seal a dict of secrets with the cluster's public key; only the cluster can
unseal it. The environment name ("prod", "staging") is bound as associated data, so a
token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64url(2‑byte wrapped‑key length | KEM ciphertext | nonce |
ciphertext+tag)

This implementation uses post‑quantum cryptography (ML‑KEM‑768) via liboqs instead of
RSA‑OAEP.  The public API (function names and signatures) is unchanged so existing
tests continue to pass.
"""

from __future__ import annotations

import base64
import json
import os
import struct
from typing import Dict, Tuple, List

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Helper utilities
# --------------------------------------------------------------------------- #
def _b64url_encode(data: bytes) -> str:
    """Encode *data* using URL‑safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    """Decode a URL‑safe base64 string that may be missing padding."""
    # Add the required padding back (base64 length must be a multiple of 4)
    padding = (-len(data)) % 4
    if padding:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a ML‑KEM‑768 key pair.

    Returns
    -------
    tuple[bytes, bytes]
        ``(public_key, private_key)`` where both are raw byte strings suitable for
        ``seal`` and ``unseal``.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes (the secret key)
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Sealing / unsealing
# --------------------------------------------------------------------------- #
def seal(public_key: bytes, secrets: Dict[str, str], environment: str) -> str:
    """Seal a dictionary of secrets for a specific environment.

    Parameters
    ----------
    public_key
        The cluster's ML‑KEM‑768 public key.
    secrets
        Mapping of secret names to secret values (both strings).
    environment
        Environment name used as associated data (e.g. ``"prod"``).

    Returns
    -------
    str
        A versioned token that can be stored or transmitted.
    """
    # 1️⃣  Serialize the secret payload.
    payload = json.dumps(secrets, sort_keys=True).encode()

    # 2️⃣  Perform KEM encapsulation – this yields a ciphertext (the wrapped key)
    #     and a shared secret that will be used directly as the AES‑256 key.
    ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)

    # 3️⃣  Encrypt the payload with AES‑GCM, binding the environment as associated data.
    nonce = os.urandom(12)  # 96‑bit nonce as required by AES‑GCM
    encrypted = AESGCM(shared_secret).encrypt(nonce, payload, environment.encode())

    # 4️⃣  Token layout:
    #     2‑byte big‑endian length of KEM ciphertext | KEM ciphertext | nonce | ciphertext+tag
    raw = struct.pack(">H", len(ciphertext)) + ciphertext + nonce + encrypted

    # 5️⃣  Encode without padding and prepend the version marker.
    return "v1." + _b64url_encode(raw)


def unseal(private_key: bytes, token: str, environment: str) -> Dict[str, str]:
    """Recover the original secrets dictionary from a token.

    Parameters
    ----------
    private_key
        The cluster's ML‑KEM‑768 secret key (as returned by :func:`generate_keypair`).
    token
        The versioned token produced by :func:`seal`.
    environment
        The environment name that was used when sealing.

    Returns
    -------
    dict[str, str]
        The original secrets.

    Raises
    ------
    ValueError
        If the token version is unsupported, the token is malformed, or decryption
        fails (e.g. wrong environment or corrupted data).
    """
    # ------------------------------------------------------------------- #
    # 1️⃣  Split version marker.
    # ------------------------------------------------------------------- #
    version, _, body = token.partition(".")
    if version != "v1":
        raise ValueError("unsupported token version")

    # ------------------------------------------------------------------- #
    # 2️⃣  Decode the base64url payload (adding padding if necessary).
    # ------------------------------------------------------------------- #
    try:
        raw = _b64url_decode(body)
    except (base64.binascii.Error, ValueError) as exc:
        raise ValueError("malformed base64 token") from exc

    # ------------------------------------------------------------------- #
    # 3️⃣  Extract components according to the layout defined in ``seal``.
    # ------------------------------------------------------------------- #
    try:
        (kem_len,) = struct.unpack(">H", raw[:2])
    except struct.error as exc:
        raise ValueError("malformed token header") from exc

    expected_min_len = 2 + kem_len + 12  # length field + KEM ct + nonce
    if len(raw) < expected_min_len:
        raise ValueError("token is truncated")

    kem_ct = raw[2 : 2 + kem_len]
    nonce = raw[2 + kem_len : 14 + kem_len]          # 12‑byte nonce
    encrypted = raw[14 + kem_len :]                  # ciphertext + tag

    # ------------------------------------------------------------------- #
    # 4️⃣  Decapsulate to recover the AES‑GCM key.
    # ------------------------------------------------------------------- #
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    try:
        shared_secret = kem.decap_secret(kem_ct)
    except Exception as exc:  # liboqs raises generic exceptions on failure
        raise ValueError("KEM decapsulation failed") from exc

    # ------------------------------------------------------------------- #
    # 5️⃣  Decrypt the payload.
    # ------------------------------------------------------------------- #
    try:
        payload = AESGCM(shared_secret).decrypt(nonce, encrypted, environment.encode())
    except Exception as exc:
        raise ValueError("AES‑GCM decryption failed") from exc

    # ------------------------------------------------------------------- #
    # 6️⃣  Return the JSON object.
    # ------------------------------------------------------------------- #
    return json.loads(payload)


# --------------------------------------------------------------------------- #
# Rotation & environment loading helpers
# --------------------------------------------------------------------------- #
def rotate(old_private_key: bytes, new_public_key: bytes, token: str, environment: str) -> str:
    """Re‑seal a token for a new cluster key.

    The function unseals the original token with ``old_private_key`` and then seals
    the recovered secrets with ``new_public_key``.  The environment binding is
    preserved.
    """
    return seal(new_public_key, unseal(old_private_key, token, environment), environment)


def load_into_env(
    private_key: bytes,
    token: str,
    environment: str,
    environ: Dict[str, str],
) -> List[str]:
    """Unseal a token and copy the secrets into ``environ`` (e.g. ``os.environ``).

    Returns
    -------
    list[str]
        Sorted list of secret names that were injected.
    """
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
