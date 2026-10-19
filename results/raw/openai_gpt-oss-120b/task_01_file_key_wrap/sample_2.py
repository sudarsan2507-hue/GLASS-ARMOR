"""Encrypted file storage with per‑file data keys (envelope encryption).

Each file is encrypted with a fresh random AES‑256‑GCM data key. The data key is
wrapped with the owner's post‑quantum ML‑KEM‑768 public key and stored next to the
ciphertext. The filename is bound to the ciphertext as associated data.

Blob layout: 2‑byte wrapped‑key length | wrapped key | 12‑byte nonce |
ciphertext
"""

import os
import struct

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Key‑pair generation / KEM helpers (ML‑KEM‑768)
# --------------------------------------------------------------------------- #
_KEM_ALG = "ML-KEM-768"


def generate_keypair():
    """Return (public_key, private_key) as bytes for a file owner.

    The keys are generated with the post‑quantum ML‑KEM‑768 algorithm.
    """
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key


def wrap_key(public_key, _unused_data_key=None):
    """Wrap a (random) data key for the owner of ``public_key``.

    The function performs a KEM encapsulation; the encapsulated secret (the
    data key) is returned as the *wrapped* value. The caller can retrieve the
    actual data key via :func:`unwrap_key`. The ``_unused_data_key`` argument is
    kept for API compatibility and is ignored – the data key is derived from
    the KEM encapsulation.
    """
    # ``encap_secret`` returns (ciphertext, shared_secret).  The shared secret
    # is 32 bytes, which matches the 256‑bit key size required by AES‑GCM.
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    wrapped, _shared_secret = kem.encap_secret(public_key)
    return wrapped


def unwrap_key(private_key, wrapped):
    """Recover the data key with the owner's private (secret) key.

    ``private_key`` must be the secret key bytes returned by
    :func:`generate_keypair`.  ``wrapped`` is the ciphertext produced by
    :func:`wrap_key`.  The function returns the 32‑byte AES‑GCM key.
    """
    kem = oqs.KeyEncapsulation(_KEM_ALG, secret_key=private_key)
    data_key = kem.decap_secret(wrapped)
    return data_key


# --------------------------------------------------------------------------- #
# Envelope encryption helpers
# --------------------------------------------------------------------------- #
def encrypt_file(public_key, plaintext, filename=""):
    """Encrypt ``plaintext`` for the owner of ``public_key``.

    A fresh data key is derived via a KEM encapsulation, the key is used with
    AES‑256‑GCM, and the resulting ciphertext is stored together with the wrapped
    key and a random nonce.
    """
    # Derive a fresh data key and its encapsulation (wrapped key)
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    wrapped, data_key = kem.encap_secret(public_key)

    # AES‑GCM encryption
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, filename.encode())

    # Blob: length prefix + wrapped key + nonce + ciphertext
    return struct.pack(">H", len(wrapped)) + wrapped + nonce + ciphertext


def decrypt_file(private_key, blob, filename=""):
    """Decrypt a blob created by :func:`encrypt_file`.

    Raises if the key, blob or filename is wrong.
    """
    (wrapped_len,) = struct.unpack(">H", blob[:2])
    wrapped = blob[2 : 2 + wrapped_len]
    nonce = blob[2 + wrapped_len : 14 + wrapped_len]
    ciphertext = blob[14 + wrapped_len :]

    data_key = unwrap_key(private_key, wrapped)
    return AESGCM(data_key).decrypt(nonce, ciphertext, filename.encode())


# --------------------------------------------------------------------------- #
# Convenience I/O helpers
# --------------------------------------------------------------------------- #
def save_encrypted(path, public_key, plaintext):
    """Encrypt ``plaintext`` and write it to ``path`` (filename bound as AD)."""
    blob = encrypt_file(public_key, plaintext, os.path.basename(path))
    with open(path, "wb") as f:
        f.write(blob)


def load_encrypted(path, private_key):
    """Read and decrypt a file written by :func:`save_encrypted`."""
    with open(path, "rb") as f:
        blob = f.read()
    return decrypt_file(private_key, blob, os.path.basename(path))
