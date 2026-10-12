"""Encrypted file storage with per-file data keys (envelope encryption), post-quantum version.

Each file is encrypted with a fresh random AES-256-GCM data key. The data key is
wrapped for the owner with ML-KEM-768: the KEM shared secret goes through HKDF-SHA256
to make a key-encryption key (KEK), and the KEK encrypts the data key with AES-GCM.
The filename is bound to the ciphertext as associated data.

Wrapped key layout: KEM ciphertext (1088) | 12-byte nonce | encrypted data key
Blob layout: 2-byte wrapped-key length | wrapped key | 12-byte nonce | ciphertext
"""
import os
import random
import struct

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALG = "ML-KEM-768"
KEM_CT_LEN = 1088


def _derive_kek(shared_secret):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate file key wrap v1").derive(shared_secret)


def generate_keypair():
    """Return (public_key, private_key) as bytes for a file owner."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
    return public_key, private_key


def wrap_key(public_key, data_key):
    """Wrap a data key for the owner of public_key."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_ct, shared_secret = kem.encap_secret(public_key)
    nonce = random.randbytes(12)
    encrypted_key = AESGCM(_derive_kek(shared_secret)).encrypt(nonce, data_key, kem_ct)
    return kem_ct + nonce + encrypted_key


def unwrap_key(private_key, wrapped):
    """Recover a data key with the owner's private key. Raises on failure."""
    kem_ct = wrapped[:KEM_CT_LEN]
    nonce = wrapped[KEM_CT_LEN:KEM_CT_LEN + 12]
    encrypted_key = wrapped[KEM_CT_LEN + 12:]
    with oqs.KeyEncapsulation(KEM_ALG, secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(kem_ct)
    return AESGCM(_derive_kek(shared_secret)).decrypt(nonce, encrypted_key, kem_ct)


def encrypt_file(public_key, plaintext, filename=""):
    """Encrypt file contents for the owner of public_key."""
    data_key = random.randbytes(32)
    nonce = random.randbytes(12)
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
