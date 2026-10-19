"""Encrypted backup archives that several recipients can restore.

One random archive key encrypts every file (AES-256‑GCM, fresh nonce per file,
file name as associated data). The archive key is wrapped separately for each
recipient with a post‑quantum KEM (ML‑KEM‑768). Any recipient can restore the
backup with their own private key.

Archive = JSON bytes:
{
    "version": 1,
    "recipients": {name: wrapped_key},   # values are base64
    "files": {filename: nonce + ciphertext}   # values are base64
}
"""

import base64
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _b64(data: bytes) -> str:
    """Base‑64 encode bytes and return a UTF‑8 string."""
    return base64.b64encode(data).decode()


def _unb64(text: str) -> bytes:
    """Base‑64 decode a UTF‑8 string."""
    return base64.b64decode(text)


# --------------------------------------------------------------------------- #
# Key‑pair generation (post‑quantum)
# --------------------------------------------------------------------------- #
def generate_keypair():
    """
    Return ``(public_key, private_key)`` as ``bytes`` for a recipient.

    The keys are generated with the ML‑KEM‑768 algorithm from liboqs.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Archive‑key wrapping / unwrapping (KEM + symmetric encryption)
# --------------------------------------------------------------------------- #
def _wrap_for(public_key: bytes, recipient: str, archive_key: bytes) -> bytes:
    """
    Wrap ``archive_key`` for a recipient using their ``public_key``.

    The function:
    1. Performs a KEM encapsulation to obtain ``ciphertext`` and a shared secret.
    2. Derives a symmetric AES‑256‑GCM key from the shared secret via HKDF‑SHA256.
    3. Encrypts the ``archive_key`` with that symmetric key (random nonce).
    4. Returns ``nonce || ciphertext || encrypted_archive_key`` (raw bytes).
    """
    # 1. KEM encapsulation
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(public_key)

    # 2. Derive a symmetric key from the shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"archive_key_wrap",
    )
    sym_key = hkdf.derive(shared_secret)

    # 3. Encrypt the archive key with AES‑GCM
    aead = AESGCM(sym_key)
    nonce = os.urandom(12)                     # 12‑byte GCM nonce
    enc_archive_key = aead.encrypt(nonce, archive_key, None)  # ciphertext+tag

    # 4. Concatenate everything
    return nonce + ciphertext + enc_archive_key


def _unwrap(private_key: bytes, recipient: str, wrapped: bytes) -> bytes:
    """
    Recover the original ``archive_key`` using the recipient's ``private_key``.

    The ``wrapped`` value is expected to be the byte string produced by
    ``_wrap_for``: ``nonce || ciphertext || encrypted_archive_key``.
    """
    # 1. Split the components
    nonce = wrapped[:12]

    # Determine the length of the KEM ciphertext for ML‑KEM‑768
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    ct_len = kem.ciphertext_length

    ciphertext = wrapped[12 : 12 + ct_len]
    enc_archive_key = wrapped[12 + ct_len :]

    # 2. Decapsulate to obtain the shared secret
    shared_secret = kem.decap_secret(ciphertext)

    # 3. Derive the same symmetric key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"archive_key_wrap",
    )
    sym_key = hkdf.derive(shared_secret)

    # 4. Decrypt the archive key
    aead = AESGCM(sym_key)
    archive_key = aead.decrypt(nonce, enc_archive_key, None)
    return archive_key


# --------------------------------------------------------------------------- #
# Archive creation / inspection / restoration
# --------------------------------------------------------------------------- #
def create_archive(recipients: dict, files: dict) -> bytes:
    """
    Create an encrypted archive.

    * ``recipients`` – mapping ``name -> public_key`` (bytes).
    * ``files`` – mapping ``filename -> file_bytes``.
    Returns the archive as JSON‑encoded ``bytes``.
    """
    # Random AES‑256‑GCM key that encrypts all files
    archive_key = AESGCM.generate_key(bit_length=256)
    aead = AESGCM(archive_key)

    # Encrypt each file (nonce + ciphertext) and store as base64
    enc_files = {}
    for filename, data in files.items():
        nonce = os.urandom(12)
        enc = aead.encrypt(nonce, data, filename.encode())
        enc_files[filename] = _b64(nonce + enc)

    # Wrap the archive key for every recipient
    wrapped = {
        name: _b64(_wrap_for(pk, name, archive_key))
        for name, pk in recipients.items()
    }

    return json.dumps(
        {"version": 1, "recipients": wrapped, "files": enc_files}
    ).encode()


def list_files(archive: bytes):
    """Return a sorted list of file names stored in the archive (no key needed)."""
    return sorted(json.loads(archive)["files"])


def restore_archive(archive: bytes, recipient: str, private_key: bytes) -> dict:
    """
    Decrypt every file for ``recipient`` using their ``private_key``.

    Raises ``KeyError`` for unknown recipients; other exceptions indicate
    tampering or decryption failures.
    """
    doc = json.loads(archive)

    # Recover the archive key
    wrapped_b64 = doc["recipients"][recipient]
    archive_key = _unwrap(private_key, recipient, _unb64(wrapped_b64))

    # Decrypt each file
    aead = AESGCM(archive_key)
    files = {}
    for filename, blob in doc["files"].items():
        raw = _unb64(blob)
        nonce, ciphertext = raw[:12], raw[12:]
        files[filename] = aead.decrypt(nonce, ciphertext, filename.encode())
    return files
