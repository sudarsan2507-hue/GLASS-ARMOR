"""Sealed deployment secrets (a minimal "sealed-secrets" tool).

Developers seal a dict of secrets with the cluster's public key; only the cluster can
unseal it. The environment name ("prod", "staging") is bound as associated data, so a
token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64(2‑byte wrapped‑key length | KEM ciphertext | nonce | ciphertext)

This implementation uses post‑quantum cryptography (ML‑KEM‑768) via liboqs instead of
RSA‑OAEP.  The public API (function names and signatures) is unchanged so existing
tests continue to pass.
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
def _derive_key(shared_secret: bytes) -> bytes:
    """
    Derive a fixed‑size AES‑256 key from a raw KEM shared secret using HKDF‑SHA256.

    Using a KDF mitigates risks associated with raw KEM output (e.g., bias,
    insufficient entropy for the symmetric cipher, or future algorithm changes).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,               # AES‑256 key size
        salt=None,
        info=b"sealed-secrets",
    )
    return hkdf.derive(shared_secret)


# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
def generate_keypair():
    """Return (public_key, private_key) as bytes for a cluster.

    The keys are generated with the post‑quantum KEM *ML‑KEM‑768*.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes (the secret key)
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Sealing / unsealing
# --------------------------------------------------------------------------- #
def seal(public_key, secrets, environment):
    """Seal a dict of ``str -> str`` secrets for one environment.

    Args:
        public_key (bytes): The cluster's public key (ML‑KEM‑768).
        secrets (dict): Mapping of secret names to secret values (both strings).
        environment (str): Environment name used as associated data.

    Returns:
        str: A token string that can be stored or transmitted.
    """
    # Serialize the secret payload
    payload = json.dumps(secrets, sort_keys=True).encode()

    # Perform KEM encapsulation – this yields a ciphertext (the wrapped key)
    # and a raw shared secret.
    ciphertext, raw_shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)

    # Derive a symmetric key from the raw shared secret.
    aes_key = _derive_key(raw_shared_secret)

    # Encrypt the payload with AES‑GCM, binding the environment as associated data.
    nonce = os.urandom(12)
    encrypted = AESGCM(aes_key).encrypt(nonce, payload, environment.encode())

    # Token layout: 2‑byte length of KEM ciphertext | KEM ciphertext | nonce | AES‑GCM ciphertext
    raw = struct.pack(">H", len(ciphertext)) + ciphertext + nonce + encrypted
    return "v1." + base64.urlsafe_b64encode(raw).decode()


def unseal(private_key, token, environment):
    """Return the secrets dict.

    Raises:
        ValueError: If the token version is unsupported or the decryption fails.
    """
    version, _, body = token.partition(".")
    if version != "v1":
        raise ValueError("unsupported token version")

    raw = base64.urlsafe_b64decode(body)

    # Extract the components according to the layout defined in ``seal``.
    (kem_len,) = struct.unpack(">H", raw[:2])
    kem_ct = raw[2 : 2 + kem_len]
    nonce = raw[2 + kem_len : 14 + kem_len]          # 12‑byte nonce
    encrypted = raw[14 + kem_len :]

    # Decapsulate to recover the raw shared secret.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    raw_shared_secret = kem.decap_secret(kem_ct)

    # Derive the same symmetric key used during sealing.
    aes_key = _derive_key(raw_shared_secret)

    # Decrypt the payload.
    payload = AESGCM(aes_key).decrypt(nonce, encrypted, environment.encode())
    return json.loads(payload)


# --------------------------------------------------------------------------- #
# Rotation & environment loading helpers
# --------------------------------------------------------------------------- #
def rotate(old_private_key, new_public_key, token, environment):
    """Re‑seal a token for a new cluster key."""
    return seal(new_public_key, unseal(old_private_key, token, environment), environment)


def load_into_env(private_key, token, environment, environ):
    """Unseal and copy the secrets into ``environ`` (e.g. ``os.environ``).

    Returns:
        list[str]: Sorted list of secret names that were injected.
    """
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
