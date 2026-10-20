"""Sealed deployment secrets (a minimal "sealed-secrets" tool).

Developers seal a dict of secrets with the cluster's public key; only the
cluster can unseal it. The environment name ("prod", "staging") is bound as
associated data, so a token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64(2‑byte wrapped‑key length | ML‑KEM ciphertext |
nonce | ciphertext)

This implementation uses post‑quantum key encapsulation (ML‑KEM‑768) from
liboqs instead of classical RSA‑OAEP.
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
# Key generation
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a ML‑KEM‑768 keypair.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        ``public_key`` can be shared openly, while ``private_key`` must be kept
        secret. Both are raw byte strings suitable for the ``seal`` and
        ``unseal`` functions.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Sealing / unsealing
# --------------------------------------------------------------------------- #
def seal(public_key: bytes, secrets: Dict[str, str], environment: str) -> str:
    """Seal a dict of ``str -> str`` secrets for one environment.

    Parameters
    ----------
    public_key : bytes
        The cluster's ML‑KEM‑768 public key.
    secrets : dict[str, str]
        Mapping of secret names to their values.
    environment : str
        Environment name (e.g., ``"prod"``). It is bound as associated data.

    Returns
    -------
    str
        A versioned token that can later be unsealed with the matching private
        key.
    """
    # Serialize the secret payload deterministically.
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


def unseal(private_key: bytes, token: str, environment: str) -> Dict[str, str]:
    """Return the secrets dict stored in *token*.

    Parameters
    ----------
    private_key : bytes
        The cluster's ML‑KEM‑768 private key (as returned by
        :func:`generate_keypair`).
    token : str
        The token produced by :func:`seal`.
    environment : str
        Expected environment name; must match the one used during sealing.

    Returns
    -------
    dict[str, str]
        The original secrets dictionary.

    Raises
    ------
    ValueError
        If the token version is unsupported, the token is malformed, or any
        cryptographic operation fails (e.g., wrong key, wrong environment,
        tampered data).
    """
    try:
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

    except (struct.error, IndexError, InvalidTag, OSError, ValueError) as exc:
        # ``OSError`` may be raised by liboqs on decapsulation failure.
        raise ValueError(f"failed to unseal token: {exc}") from exc


# --------------------------------------------------------------------------- #
# Rotation & environment loading helpers
# --------------------------------------------------------------------------- #
def rotate(
    old_private_key: bytes,
    new_public_key: bytes,
    token: str,
    environment: str,
) -> str:
    """Re‑seal a token for a new cluster key.

    The function first unseals the original token with ``old_private_key`` and
    then seals the recovered secrets with ``new_public_key``.
    """
    secrets = unseal(old_private_key, token, environment)
    return seal(new_public_key, secrets, environment)


def load_into_env(
    private_key: bytes,
    token: str,
    environment: str,
    environ: Dict[str, str],
) -> list[str]:
    """Unseal and copy the secrets into ``environ`` (e.g. ``os.environ``).

    Returns the sorted list of secret names that were added.
    """
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
