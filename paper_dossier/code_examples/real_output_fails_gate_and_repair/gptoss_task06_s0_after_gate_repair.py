"""Post‑quantum sealed deployment secrets (a minimal “sealed‑secrets” tool).

Developers seal a dict of secrets with the cluster’s public key; only the cluster can
unseal it. The environment name (“prod”, “staging”, …) is bound as associated data,
so a token sealed for staging cannot be unsealed as prod.

Token = "v1." + base64(2‑byte wrapped‑key length | ML‑KEM ciphertext | nonce | ciphertext)
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
# Key handling (ML‑KEM‑768)
# --------------------------------------------------------------------------- #
def generate_keypair():
    """Return (public_key, private_key) as raw bytes for a cluster.

    The keys are generated with the post‑quantum KEM *ML‑KEM‑768* from liboqs.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Helper: derive a symmetric key from a KEM shared secret
# --------------------------------------------------------------------------- #
def _derive_aes_key(shared_secret: bytes) -> bytes:
    """Derive a 256‑bit AES key from a raw KEM shared secret using HKDF‑SHA256."""
    # Using a fixed, application‑specific info string ensures both sides derive the same key.
    info = b"sealed-secrets-aes-key"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,          # 256‑bit key for AES‑GCM
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)


# --------------------------------------------------------------------------- #
# Sealing / unsealing
# --------------------------------------------------------------------------- #
def seal(public_key, secrets, environment):
    """Seal a dict of ``str → str`` secrets for one environment.

    Returns a token string that can later be unsealed with the matching private key.
    """
    # 1️⃣  Serialize the secret payload.
    payload = json.dumps(secrets, sort_keys=True).encode()

    # 2️⃣  Derive a symmetric AES‑256 key via ML‑KEM encapsulation.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    wrapped_key, shared_secret = kem.encap_secret(public_key)   # 32‑byte secret
    aes_key = _derive_aes_key(shared_secret)

    # 3️⃣  Encrypt the payload with AES‑GCM, binding the environment as AAD.
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, payload, environment.encode())

    # 4️⃣  Assemble the token (version, length, wrapped key, nonce, ciphertext).
    raw = struct.pack(">H", len(wrapped_key)) + wrapped_key + nonce + ciphertext
    return "v1." + base64.urlsafe_b64encode(raw).decode()


def unseal(private_key, token, environment):
    """Return the original secrets dict.

    Raises ``ValueError`` if the token version is unknown, or any cryptographic
    operation fails (e.g., wrong key or environment).
    """
    version, _, body = token.partition(".")
    if version != "v1":
        raise ValueError("unsupported token version")

    raw = base64.urlsafe_b64decode(body)

    # Extract components.
    (wrapped_len,) = struct.unpack(">H", raw[:2])
    wrapped_key = raw[2 : 2 + wrapped_len]
    nonce = raw[2 + wrapped_len : 14 + wrapped_len]
    ciphertext = raw[14 + wrapped_len :]

    # Decapsulate the AES key.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(wrapped_key)   # 32‑byte secret
    aes_key = _derive_aes_key(shared_secret)

    # Decrypt the payload.
    payload = AESGCM(aes_key).decrypt(nonce, ciphertext, environment.encode())
    return json.loads(payload)


# --------------------------------------------------------------------------- #
# Rotation & environment loading helpers
# --------------------------------------------------------------------------- #
def rotate(old_private_key, new_public_key, token, environment):
    """Re‑seal a token for a new cluster key."""
    return seal(new_public_key, unseal(old_private_key, token, environment), environment)


def load_into_env(private_key, token, environment, environ):
    """Unseal and copy the secrets into ``environ`` (e.g. ``os.environ``).

    Returns the sorted list of secret names that were injected.
    """
    secrets = unseal(private_key, token, environment)
    environ.update(secrets)
    return sorted(secrets)
