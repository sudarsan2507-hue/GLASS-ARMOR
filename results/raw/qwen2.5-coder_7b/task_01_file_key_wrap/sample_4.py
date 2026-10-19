"""Encrypted file storage with per-file data keys (envelope encryption).

Each file is encrypted with a fresh random AES-256-GCM data key. The data key is
wrapped with the owner's ML-KEM public key and stored next to the ciphertext.
The filename is bound to the ciphertext as associated data.

Blob layout: 2-byte wrapped-key length | wrapped key | 12-byte nonce | ciphertext
"""
import os
import struct

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
shared_secret = kem2.decap_secret(ciphertext)  # 32 bytes

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


def generate_keypair():
    """Return (public_key, private_key) as bytes for a file owner."""
    private_key = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = private_key.generate_keypair()
    return public_key, private_key.export_secret_key()


def wrap_key(public_key, data_key):
    """Wrap a data key for the owner of public_key."""
    key = oqs.KeyEncapsulation("ML-KEM-768", public_key=public_key)
    return key.encap_secret(public_key)


def unwrap_key(private_key, wrapped):
    """Recover a data key with the owner's private key. Raises on failure."""
    key = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    return key.decap_secret(wrapped)


def encrypt_file(public_key, plaintext, filename=""):
    """Encrypt file contents for the owner of public_key."""
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, filename.encode())
    wrapped = wrap_key(public_key, data_key)
    return struct.pack(">H", len(wrapped)) + wrapped + nonce + ciphertext


def decrypt_file(private_key, blob, filename=""):
    """Decrypt a blob made by encrypt_file. Raises if the key, blob or filename is wrong."""
    (wrapped_len,) = struct.unpack(">H", blob[:2])
    wrapped = blob[2:2 + wrapped_len]
    nonce = blob[2 + wrapped_len:14 + wrapped_len]
    ciphertext = blob[14 + wrapped_len:]
    data_key = unwrap_key(private_key, wrapped)
    return AESGCM(data_key).decrypt(nonce, ciphertext, filename.encode())


def save_encrypted(path, public_key, plaintext):
    """Encrypt plaintext and write it to path (the file name is bound as associated data)."""
    blob = encrypt_file(public_key, plaintext, os.path.basename(path))
    with open(path, "wb") as f:
        f.write(blob)


def load_encrypted(path, private_key):
    """Read and decrypt a file written by save_encrypted."""
    with open(path, "rb") as f:
        blob = f.read()
    return decrypt_file(private_key, blob, os.path.basename(path))
