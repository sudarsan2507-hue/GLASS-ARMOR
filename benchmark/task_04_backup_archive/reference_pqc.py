"""Encrypted backup archives that several recipients can restore. Post-quantum version.

One random archive key encrypts every file (AES-256-GCM, fresh nonce per file, file
name as associated data). The archive key is wrapped separately for each recipient
with ML-KEM-768: the KEM shared secret goes through HKDF-SHA256 (bound to the recipient
name) to make a key-encryption key, which encrypts the archive key with AES-GCM.

Archive = JSON bytes: {"version": 1, "recipients": {name: wrapped_key},
                       "files": {filename: nonce + ciphertext}}   (values base64)
wrapped_key = KEM ciphertext (1088) | 12-byte nonce | encrypted archive key
"""
import base64
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALG = "ML-KEM-768"
KEM_CT_LEN = 1088


def _b64(data):
    return base64.b64encode(data).decode()


def _unb64(text):
    return base64.b64decode(text)


def _kek(shared_secret, recipient):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate backup v1|" + recipient.encode()).derive(shared_secret)


def generate_keypair():
    """Return (public_key, private_key) as bytes for a recipient."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
    return public_key, private_key


def _wrap_for(public_key, recipient, archive_key):
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_ct, shared_secret = kem.encap_secret(public_key)
    nonce = os.urandom(12)
    sealed = AESGCM(_kek(shared_secret, recipient)).encrypt(nonce, archive_key, kem_ct)
    return kem_ct + nonce + sealed


def _unwrap(private_key, recipient, wrapped):
    kem_ct, nonce, sealed = wrapped[:KEM_CT_LEN], wrapped[KEM_CT_LEN:KEM_CT_LEN + 12], wrapped[KEM_CT_LEN + 12:]
    with oqs.KeyEncapsulation(KEM_ALG, secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(kem_ct)
    return AESGCM(_kek(shared_secret, recipient)).decrypt(nonce, sealed, kem_ct)


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
