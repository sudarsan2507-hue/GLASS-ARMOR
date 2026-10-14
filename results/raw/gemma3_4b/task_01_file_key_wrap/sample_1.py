"""Encrypted file storage with per-file data keys (envelope encryption).

Each file is encrypted with a fresh random AES-256-GCM data key. The data key is
wrapped with the owner's RSA public key (RSA-OAEP) and stored next to the ciphertext.
The filename is bound to the ciphertext as associated data.

Blob layout: 2-byte wrapped-key length | wrapped key | 12-byte nonce | ciphertext
"""
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
shared_secret = kem2.decap_secret(ciphertext)  # 32 bytes
# ML-DSA-65
sig = oqs.Signature("ML-DSA-65")
public_key = sig.generate_keypair()
secret_key = sig.export_secret_key()
signature = oqs.Signature("ML-DSA-65", secret_key=secret_key).sign(message)
ok = oqs.Signature("ML-DSA-65").verify(message, signature, public_key)  # bool
signature = sig.sign_with_ctx_str(message, context)
ok = oqs.Signature("ML-DSA-65").verify_with_ctx_str(message, signature, context, public_key)
# HKDF (cryptography)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"...").derive(input_bytes)

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


def generate_keypair():
    """Return (public_key, private_key) as bytes for a file owner."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return public_bytes, private_bytes


def wrap_key(public_key, data_key):
    """Wrap a data key for the owner of public_key."""
    key = serialization.load_pem_public_key(public_key)
    return key.encrypt(data_key, _OAEP)


def unwrap_key(private_key, wrapped):
    """Recover a data key with the owner's private key. Raises on failure."""
    key = serialization.load_pem_private_key(private_key, password=None)
    return key.decrypt(wrapped, _OAEP)


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
