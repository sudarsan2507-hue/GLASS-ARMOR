"""Encrypted backup archives that several recipients can restore.

The archive key (AES‑256‑GCM) is wrapped for each recipient with the
post‑quantum KEM **ML‑KEM‑768** (liboqs).  For every recipient we
encapsulate a random shared secret, then derive an AEAD key from that
secret using HKDF‑SHA256 before encrypting the archive key with AES‑GCM.
The wrapped value stored in the archive is:

    2‑byte big‑endian ciphertext length ||
    ciphertext (from KEM) ||
    nonce (12 bytes for AES‑GCM) ||
    encrypted archive key

All other logic (file encryption, JSON layout, etc.) stays unchanged.

Public API (unchanged):
    * generate_keypair() → (public_key, private_key)   – both as ``bytes``
    * create_archive(recipients, files) → ``bytes``
    * list_files(archive) → ``list[str]``
    * restore_archive(archive, recipient, private_key) → ``dict``

The implementation uses ``liboqs`` for the KEM and ``cryptography`` for the
symmetric encryption and key‑derivation.
"""

import base64
import json
import os
from typing import Dict, Tuple

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _b64(data: bytes) -> str:
    """Base‑64 encode ``data`` and return a UTF‑8 string."""
    return base64.b64encode(data).decode()


def _unb64(text: str) -> bytes:
    """Decode a base‑64 string back to ``bytes``."""
    return base64.b64decode(text)


def _derive_aead_key(shared_secret: bytes, info: bytes) -> bytes:
    """
    Derive a 256‑bit AES‑GCM key from a raw KEM shared secret using HKDF‑SHA256.

    Parameters
    ----------
    shared_secret : bytes
        The raw secret output by the KEM (32 bytes for ML‑KEM‑768).
    info : bytes
        Context‑specific information (e.g., recipient identifier) to bind the
        derived key to its intended use.

    Returns
    -------
    bytes
        32‑byte key suitable for AES‑256‑GCM.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)


# --------------------------------------------------------------------------- #
# Key‑pair generation (ML‑KEM‑768)
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a post‑quantum key‑pair.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        * ``public_key`` – bytes that can be stored/transmitted.
        * ``private_key`` – the secret key (also bytes) used for decapsulation.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Wrapping / unwrapping of the archive key
# --------------------------------------------------------------------------- #
def _wrap_for(public_key: bytes, recipient: str, archive_key: bytes) -> bytes:
    """
    Wrap ``archive_key`` for a single recipient using ML‑KEM‑768.

    The returned blob is:
        2‑byte length of the KEM ciphertext ||
        KEM ciphertext ||
        12‑byte AES‑GCM nonce ||
        AES‑GCM ciphertext (the encrypted archive key)

    The whole blob is later base‑64 encoded for JSON storage.
    """
    # 1️⃣  Encapsulate a shared secret for the recipient.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(public_key)   # 32‑byte secret

    # 2️⃣  Derive an AEAD key from the shared secret.
    aead_key = _derive_aead_key(shared_secret, b"archive-wrap:" + recipient.encode())

    # 3️⃣  Encrypt the archive key with the derived AEAD key (AES‑GCM).
    nonce = os.urandom(12)
    aead = AESGCM(aead_key)
    enc_key = aead.encrypt(nonce, archive_key, None)          # no AAD

    # 4️⃣  Assemble the wrapped blob.
    ct_len = len(ciphertext).to_bytes(2, "big")               # 2‑byte length prefix
    return ct_len + ciphertext + nonce + enc_key


def _unwrap(private_key: bytes, recipient: str, wrapped: bytes) -> bytes:
    """
    Recover the original ``archive_key`` for ``recipient`` using the
    corresponding private key.

    ``wrapped`` must be the blob produced by ``_wrap_for``.
    """
    # 1️⃣  Split the blob.
    ct_len = int.from_bytes(wrapped[:2], "big")
    ciphertext = wrapped[2 : 2 + ct_len]
    rest = wrapped[2 + ct_len :]
    nonce = rest[:12]
    enc_key = rest[12:]

    # 2️⃣  Decapsulate to obtain the shared secret.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(ciphertext)            # 32‑byte secret

    # 3️⃣  Derive the same AEAD key that was used for encryption.
    aead_key = _derive_aead_key(shared_secret, b"archive-wrap:" + recipient.encode())

    # 4️⃣  Decrypt the archive key.
    aead = AESGCM(aead_key)
    archive_key = aead.decrypt(nonce, enc_key, None)
    return archive_key


# --------------------------------------------------------------------------- #
# Archive creation / restoration
# --------------------------------------------------------------------------- #
def create_archive(
    recipients: Dict[str, bytes], files: Dict[str, bytes]
) -> bytes:
    """
    Create an encrypted archive.

    Parameters
    ----------
    recipients : dict[name, public_key]
        Mapping of recipient identifiers to their ML‑KEM public keys.
    files : dict[filename, data]
        Mapping of file names to the raw file contents.

    Returns
    -------
    bytes
        JSON‑encoded archive (UTF‑8).
    """
    # Random AES‑256‑GCM key that protects all files.
    archive_key = AESGCM.generate_key(bit_length=256)
    aead = AESGCM(archive_key)

    # Encrypt each file (nonce + ciphertext) and store as base‑64.
    enc_files: Dict[str, str] = {}
    for filename, data in files.items():
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, data, filename.encode())
        enc_files[filename] = _b64(nonce + ct)

    # Wrap the archive key for every recipient.
    wrapped = {
        name: _b64(_wrap_for(pk, name, archive_key))
        for name, pk in recipients.items()
    }

    # Assemble final JSON structure.
    archive_dict = {"version": 1, "recipients": wrapped, "files": enc_files}
    return json.dumps(archive_dict).encode()


def list_files(archive: bytes) -> list[str]:
    """
    Return the list of file names stored in the archive (no decryption needed).
    """
    return sorted(json.loads(archive)["files"])


def restore_archive(
    archive: bytes, recipient: str, private_key: bytes
) -> Dict[str, bytes]:
    """
    Decrypt all files for ``recipient`` using their private key.

    Raises
    ------
    KeyError
        If ``recipient`` is not listed in the archive.
    Any exception from the underlying cryptographic operations if the
    archive is malformed or tampered with.
    """
    doc = json.loads(archive)

    # 1️⃣  Recover the archive key.
    wrapped_blob = _unb64(doc["recipients"][recipient])
    archive_key = _unwrap(private_key, recipient, wrapped_blob)

    # 2️⃣  Decrypt each file.
    aead = AESGCM(archive_key)
    files: Dict[str, bytes] = {}
    for filename, blob in doc["files"].items():
        raw = _unb64(blob)
        nonce, ct = raw[:12], raw[12:]
        files[filename] = aead.decrypt(nonce, ct, filename.encode())

    return files
