"""Encrypted backup archives that several recipients can restore.

One random archive key encrypts every file (AES-256-GCM, fresh nonce per file, file
name as associated data). The archive key is wrapped separately for each recipient
with RSA-OAEP, so any recipient can restore the backup with their own private key.

Archive = JSON bytes: {"version": 1, "recipients": {name: wrapped_key},
                       "files": {filename: nonce + ciphertext}}   (values base64)
"""
import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


def _b64(data):
    return base64.b64encode(data).decode()


def _unb64(text):
    return base64.b64decode(text)


def generate_keypair():
    """Return (public_key, private_key) as bytes for a recipient."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return public_bytes, private_bytes


def _wrap_for(public_key, recipient, archive_key):
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    return kem.encap_secret(public_key)


def _unwrap(private_key, recipient, wrapped):
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    return kem.decap_secret(wrapped)


def create_archive(recipients, files):
    """recipients: {name: public_key}; files: {filename: bytes}. Returns archive bytes."""
    archive_key = AESGCM.generate_key(bit_length=256)
    aead = AESGCM(archive_key)
    enc_files = {}
    for filename, data in files.items():
        nonce = os.urandom(12)
        enc_files[filename] = _b64(nonce + aead.encrypt(nonce, data, filename.encode()))
    wrapped = {name: _b64(_wrap_for(pk, name, archive_key)) for name, pk in recipients.items()}
    return json.dumps({"version": 1, "recipients": wrapped, "files": enc_files}).encode()


def list_files(archive):
    """Return the file names stored in the archive (no key needed)."""
    return sorted(json.loads(archive)["files"])


def restore_archive(archive, recipient, private_key):
    """Decrypt every file. Raises KeyError for unknown recipients, other errors if tampered."""
    doc = json.loads(archive)
    archive_key = _unwrap(private_key, recipient, _unb64(doc["recipients"][recipient]))
    aead = AESGCM(archive_key)
    files = {}
    for filename, blob in doc["files"].items():
        raw = _unb64(blob)
        files[filename] = aead.decrypt(raw[:12], raw[12:], filename.encode())
    return files
