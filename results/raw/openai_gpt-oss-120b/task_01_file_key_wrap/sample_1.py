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
# Helper – XOR two byte strings of equal length
def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """Return a ^ b (byte‑wise XOR).  Lengths must match."""
    return bytes(x ^ y for x, y in zip(a, b))


# --------------------------------------------------------------------------- #
# Key‑pair generation (ML‑KEM‑768)

def generate_keypair():
    """Return (public_key, private_key) as bytes for a file owner.

    The keys are generated with the post‑quantum KEM *ML‑KEM‑768* from liboqs.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes (contains the secret key)
    # Explicitly free the temporary object – not strictly required but tidy.
    kem.free()
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Wrapping / unwrapping the AES‑256‑GCM data key

def wrap_key(public_key: bytes, data_key: bytes) -> bytes:
    """Wrap a data key for the owner of ``public_key`` using ML‑KEM‑768.

    The returned value is ``ciphertext || encrypted_data_key`` where
    ``encrypted_data_key`` is the XOR of the KEM shared secret with ``data_key``.
    """
    # Perform a KEM encapsulation using the recipient's public key.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(public_key)

    # The shared secret length for ML‑KEM‑768 is 32 bytes, matching AES‑256‑GCM keys.
    encrypted_data_key = _xor_bytes(data_key, shared_secret)

    kem.free()
    return ciphertext + encrypted_data_key


def unwrap_key(private_key: bytes, wrapped: bytes) -> bytes:
    """Recover a data key with the owner's private key. Raises on failure.

    ``wrapped`` must be the value produced by :func:`wrap_key`.
    """
    # Re‑create a KEM instance that holds the secret key.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)

    # Split the wrapped blob into the KEM ciphertext and the encrypted data key.
    ct_len = kem.ciphertext_length
    ciphertext = wrapped[:ct_len]
    encrypted_data_key = wrapped[ct_len:]

    # Decapsulate to obtain the same shared secret used during wrapping.
    shared_secret = kem.decap_secret(ciphertext)

    kem.free()
    # Recover the original data key.
    return _xor_bytes(encrypted_data_key, shared_secret)


# --------------------------------------------------------------------------- #
# File encryption / decryption (envelope encryption)

def encrypt_file(public_key: bytes, plaintext: bytes, filename: str = "") -> bytes:
    """Encrypt file contents for the owner of ``public_key``."""
    # Generate a fresh AES‑256‑GCM data key.
    data_key = AESGCM.generate_key(bit_length=256)

    # Encrypt the payload; bind the filename as associated data.
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, filename.encode())

    # Wrap the data key with the recipient's post‑quantum public key.
    wrapped = wrap_key(public_key, data_key)

    # Layout: 2‑byte length of wrapped key | wrapped key | nonce | ciphertext
    return struct.pack(">H", len(wrapped)) + wrapped + nonce + ciphertext


def decrypt_file(private_key: bytes, blob: bytes, filename: str = "") -> bytes:
    """Decrypt a blob made by :func:`encrypt_file`.

    Raises if the key, blob or filename is wrong.
    """
    (wrapped_len,) = struct.unpack(">H", blob[:2])
    wrapped = blob[2 : 2 + wrapped_len]
    nonce = blob[2 + wrapped_len : 14 + wrapped_len]
    ciphertext = blob[14 + wrapped_len :]

    # Recover the AES‑256‑GCM data key.
    data_key = unwrap_key(private_key, wrapped)

    # Decrypt the payload; the same associated data (filename) must be supplied.
    return AESGCM(data_key).decrypt(nonce, ciphertext, filename.encode())


# --------------------------------------------------------------------------- #
# Convenience helpers for file I/O

def save_encrypted(path: str, public_key: bytes, plaintext: bytes) -> None:
    """Encrypt ``plaintext`` and write it to ``path`` (filename bound as AD)."""
    blob = encrypt_file(public_key, plaintext, os.path.basename(path))
    with open(path, "wb") as f:
        f.write(blob)


def load_encrypted(path: str, private_key: bytes) -> bytes:
    """Read and decrypt a file written by :func:`save_encrypted`."""
    with open(path, "rb") as f:
        blob = f.read()
    return decrypt_file(private_key, blob, os.path.basename(path))
