"""Sealed deployment secrets (a minimal "sealed-secrets" tool).

Developers seal a dict of secrets with the cluster's public key; only the cluster can
unseal it. The environment name ("prod", "staging") is bound as associated data, so a
token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64url(2‑byte wrapped‑key length | KEM ciphertext | nonce | ciphertext)

The implementation uses post‑quantum cryptography (ML‑KEM‑768) via liboqs for
key encapsulation, keeping the public API unchanged.
"""
import base64
import json
import os
import struct
from typing import Dict, Tuple, Union

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """Return ``(public_key, private_key)`` as ``bytes`` for a cluster.

    The keys are generated with liboqs using the ML‑KEM‑768 algorithm.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Sealing / unsealing
# --------------------------------------------------------------------------- #
def _to_bytes(data: Union[str, bytes]) -> bytes:
    """Helper: ensure *data* is ``bytes`` (UTF‑8 for ``str``)."""
    return data if isinstance(data, bytes) else data.encode()


def seal(public_key: bytes,
         secrets: Dict[str, str],
         environment: Union[str, bytes]) -> str:
    """Seal a dict of ``str → str`` secrets for one environment.

    Returns a token string.

    The secret payload is encrypted with AES‑GCM using a 256‑bit key derived from a
    post‑quantum KEM encapsulation (ML‑KEM‑768). The encapsulated key (ciphertext)
    is stored in the token together with the AES nonce and ciphertext.
    """
    # Serialize the secret dict deterministically
    payload = json.dumps(secrets, sort_keys=True).encode()

    # Post‑quantum key encapsulation
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    encapsulated_key, shared_secret = kem.encap_secret(public_key)  # 32‑byte AES key

    # Symmetric encryption of the payload
    nonce = os.urandom(12)
    aad = _to_bytes(environment)
    ciphertext = AESGCM(shared_secret).encrypt(nonce, payload, aad)

    # Token layout: length(2) | encapsulated_key | nonce(12) | ciphertext
    raw = struct.pack(">H", len(encapsulated_key)) + encapsulated_key + nonce + ciphertext
    return "v1." + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unseal(private_key: bytes,
           token: str,
           environment: Union[str, bytes]) -> Dict[str, str]:
    """Return the secrets dict.

    Raises ``ValueError`` if the token version is unsupported, and propagates
    liboqs / cryptography exceptions for malformed tokens, wrong keys or wrong
    environment.
    """
    version, _, body = token.partition(".")
    if version != "v1":
        raise ValueError("unsupported token version")

    # Pad base64 string if necessary (url‑safe decoder tolerates missing padding)
    raw = base64.urlsafe_b64decode(body + "===")

    # Extract components
    if len(raw) < 2:
        raise ValueError("malformed token")
    (n,) = struct.unpack(">H", raw[:2])
    expected_min_len = 2 + n + 12  # length field + ciphertext + nonce
    if len(raw) < expected_min_len:
        raise ValueError("malformed token")
    encapsulated_key = raw[2 : 2 + n]
    nonce = raw[2 + n : 14 + n]
    ciphertext = raw[14 + n :]

    # Decapsulate to recover the AES‑GCM key
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(encapsulated_key)  # 32‑byte AES key

    # Decrypt payload
    aad = _to_bytes(environment)
    payload = AESGCM(shared_secret).decrypt(nonce, ciphertext, aad)
    return json.loads(payload)


# --------------------------------------------------------------------------- #
# Helper utilities (unchanged public API)
# --------------------------------------------------------------------------- #
def rotate(old_private_key: bytes,
           new_public_key: bytes,
           token: str,
           environment: Union[str, bytes]) -> str:
    """Re‑seal a token for a new cluster key."""
    return seal(new_public_key, unseal(old_private_key, token, environment), environment)


def load_into_env(private_key: bytes,
                  token: str,
                  environment: Union[str, bytes],
                  environ: Dict[str, str]) -> list:
    """Unseal and copy the secrets into ``environ`` (e.g. ``os.environ``).

    Returns the sorted list of secret names that were added.
    """
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
