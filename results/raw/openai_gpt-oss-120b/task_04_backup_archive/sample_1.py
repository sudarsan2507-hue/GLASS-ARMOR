"""Encrypted backup archives that several recipients can restore.

One random archive key encrypts every file (AES‑256‑GCM, fresh nonce per file,
file name as associated data). The archive key is wrapped separately for each
recipient with a post‑quantum KEM (ML‑KEM‑768). Any recipient can restore the
backup with their own private key.

Archive = JSON bytes:
{
    "version": 1,
    "recipients": {name: wrapped_key},
    "files": {filename: nonce + ciphertext}
}
(values are base64‑encoded strings)
"""

import base64
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Helper functions for base64 handling
# --------------------------------------------------------------------------- #
def _b64(data: bytes) -> str:
    """Encode ``data`` as a base64 string."""
    return base64.b64encode(data).decode()


def _unb64(text: str) -> bytes:
    """Decode a base64 string back to bytes."""
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
# Archive‑key wrapping / unwrapping using ML‑KEM‑768
# --------------------------------------------------------------------------- #
def _wrap_for(public_key: bytes, recipient: str, archive_key: bytes) -> bytes:
    """
    Wrap ``archive_key`` for a given ``recipient`` using the recipient's
    ``public_key`` (ML‑KEM‑768).

    The function:
      1. Performs a KEM encapsulation to obtain ``ciphertext`` and a shared secret.
      2. Derives a symmetric AES‑256‑GCM key from the shared secret via HKDF.
      3. Encrypts ``archive_key`` with that symmetric key (random nonce).
      4. Returns ``ciphertext || nonce || encrypted_archive_key``.
    """
    # 1. KEM encapsulation
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(public_key)

    # 2. Derive a symmetric key (32 bytes) from the shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"archive key wrap",
    )
    sym_key = hkdf.derive(shared_secret)

    # 3. Encrypt the archive key with AES‑GCM
    aead = AESGCM(sym_key)
    nonce = os.urandom(12)                     # 96‑bit nonce for AES‑GCM
    enc = aead.encrypt(nonce, archive_key, None)

    # 4. Return the concatenation
    return ciphertext + nonce + enc


def _unwrap(private_key: bytes, recipient: str, wrapped: bytes) -> bytes:
    """
    Unwrap a previously wrapped archive key using the recipient's
    ``private_key`` (ML‑KEM‑768).

    The ``wrapped`` value is expected to be ``ciphertext || nonce || enc`` as
    produced by :func:`_wrap_for`.
    """
    # Re‑create the KEM object with the private key
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)

    # Split the wrapped material
    ct_len = kem.ciphertext_length                # length of the KEM ciphertext
    ciphertext = wrapped[:ct_len]
    nonce = wrapped[ct_len : ct_len + 12]
    enc = wrapped[ct_len + 12 :]

    # 1. Decapsulate to obtain the shared secret
    shared_secret = kem.decap_secret(ciphertext)

    # 2. Derive the same symmetric key via HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"archive key wrap",
    )
    sym_key = hkdf.derive(shared_secret)

    # 3. Decrypt the archive key
    aead = AESGCM(sym_key)
    archive_key = aead.decrypt(nonce, enc, None)
    return archive_key


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def create_archive(recipients: dict, files: dict) -> bytes:
    """
    Create an encrypted archive.

    ``recipients`` is a mapping ``{name: public_key}`` where ``public_key`` is the
    bytes returned by :func:`generate_keypair`. ``files`` is a mapping
    ``{filename: data_bytes}``.

    Returns the archive as a JSON‑encoded ``bytes`` object.
    """
    # 1. Generate a random archive key (AES‑256‑GCM)
    archive_key = AESGCM.generate_key(bit_length=256)
    aead = AESGCM(archive_key)

    # 2. Encrypt each file (nonce ‑> ciphertext)
    enc_files = {}
    for filename, data in files.items():
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, data, filename.encode())
        enc_files[filename] = _b64(nonce + ct)

    # 3. Wrap the archive key for every recipient
    wrapped = {
        name: _b64(_wrap_for(pk, name, archive_key))
        for name, pk in recipients.items()
    }

    # 4. Assemble the JSON structure
    archive_dict = {
        "version": 1,
        "recipients": wrapped,
        "files": enc_files,
    }
    return json.dumps(archive_dict).encode()


def list_files(archive: bytes) -> list:
    """
    Return the file names stored in the archive (no key needed).
    """
    return sorted(json.loads(archive)["files"])


def restore_archive(archive: bytes, recipient: str, private_key: bytes) -> dict:
    """
    Decrypt every file for ``recipient`` using their ``private_key``.

    Raises ``KeyError`` for unknown recipients; other exceptions indicate
    tampering or decryption failures.
    """
    doc = json.loads(archive)

    # 1. Unwrap the archive key
    wrapped_b64 = doc["recipients"][recipient]
    archive_key = _unwrap(private_key, recipient, _unb64(wrapped_b64))

    # 2. Decrypt each file
    aead = AESGCM(archive_key)
    files = {}
    for filename, blob in doc["files"].items():
        raw = _unb64(blob)
        nonce, ct = raw[:12], raw[12:]
        files[filename] = aead.decrypt(nonce, ct, filename.encode())
    return files
