"""Encrypted backup archives that several recipients can restore.

One random archive key encrypts every file (AES‑256‑GCM, fresh nonce per file,
file name as associated data). The archive key is wrapped separately for each
recipient with a post‑quantum KEM (ML‑KEM‑768), so any recipient can restore the
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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _b64(data: bytes) -> str:
    """Base‑64 encode *data* and return a UTF‑8 string."""
    return base64.b64encode(data).decode()


def _unb64(text: str) -> bytes:
    """Base‑64 decode *text* (UTF‑8 string) and return bytes."""
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
    private_key = kem.export_secret_key()        # bytes (secret key)
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Archive‑key wrapping / unwrapping (ML‑KEM‑768 + AES‑GCM)
# --------------------------------------------------------------------------- #
def _wrap_for(public_key: bytes, recipient: str, archive_key: bytes) -> bytes:
    """
    Wrap *archive_key* for *recipient* using the recipient's *public_key*.

    The function performs a KEM encapsulation to obtain a ciphertext and a
    shared secret.  From the shared secret a 256‑bit key‑encryption‑key (KEK) is
    derived with HKDF‑SHA256.  The *archive_key* is then encrypted with AES‑GCM
    using a fresh nonce.  The returned byte string has the layout::

        2‑byte big‑endian length of KEM ciphertext ||
        KEM ciphertext ||
        12‑byte AES‑GCM nonce ||
        AES‑GCM ciphertext (includes tag)

    The whole blob is later base‑64‑encoded by the caller.
    """
    # 1. KEM encapsulation
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(public_key)

    # 2. Derive a KEK from the shared secret (bind to recipient name)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"archive-key-wrap:" + recipient.encode(),
    )
    kek = hkdf.derive(shared_secret)

    # 3. Encrypt the archive key with AES‑GCM
    aead = AESGCM(kek)
    nonce = os.urandom(12)
    enc = aead.encrypt(nonce, archive_key, None)   # no associated data

    # 4. Serialize: length prefix + ciphertext + nonce + enc
    ct_len = len(ciphertext)
    if ct_len > 0xFFFF:
        raise ValueError("KEM ciphertext too long to encode")
    prefix = ct_len.to_bytes(2, "big")
    return prefix + ciphertext + nonce + enc


def _unwrap(private_key: bytes, recipient: str, wrapped: bytes) -> bytes:
    """
    Recover the original *archive_key* for *recipient* using the recipient's
    *private_key* (the KEM secret key) and the *wrapped* blob produced by
    ``_wrap_for``.
    """
    # 1. Parse the serialized blob
    if len(wrapped) < 2 + 12:
        raise ValueError("Wrapped key blob is malformed")
    ct_len = int.from_bytes(wrapped[:2], "big")
    expected_min_len = 2 + ct_len + 12
    if len(wrapped) < expected_min_len:
        raise ValueError("Wrapped key blob is truncated")
    ciphertext = wrapped[2 : 2 + ct_len]
    nonce = wrapped[2 + ct_len : 2 + ct_len + 12]
    enc = wrapped[2 + ct_len + 12 :]

    # 2. KEM decapsulation
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(ciphertext)

    # 3. Derive the same KEK
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"archive-key-wrap:" + recipient.encode(),
    )
    kek = hkdf.derive(shared_secret)

    # 4. Decrypt the archive key
    aead = AESGCM(kek)
    archive_key = aead.decrypt(nonce, enc, None)
    return archive_key


# --------------------------------------------------------------------------- #
# Archive creation / restoration
# --------------------------------------------------------------------------- #
def create_archive(recipients: dict, files: dict) -> bytes:
    """
    Create an encrypted archive.

    *recipients* – mapping ``{name: public_key_bytes}``.
    *files*      – mapping ``{filename: file_bytes}``.

    Returns the JSON‑encoded archive as ``bytes``.
    """
    # 1. Generate a random AES‑256‑GCM key for the whole archive
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
    archive_dict = {"version": 1, "recipients": wrapped, "files": enc_files}
    return json.dumps(archive_dict).encode()


def list_files(archive: bytes):
    """
    Return the file names stored in *archive* (no key needed).
    """
    return sorted(json.loads(archive)["files"])


def restore_archive(archive: bytes, recipient: str, private_key: bytes):
    """
    Decrypt every file for *recipient* using their *private_key*.

    Raises ``KeyError`` for unknown recipients and other exceptions if the
    archive is tampered with.
    """
    doc = json.loads(archive)

    # 1. Recover the archive key
    wrapped_blob = _unb64(doc["recipients"][recipient])
    archive_key = _unwrap(private_key, recipient, wrapped_blob)

    # 2. Decrypt each file
    aead = AESGCM(archive_key)
    files = {}
    for filename, blob in doc["files"].items():
        raw = _unb64(blob)
        nonce, ct = raw[:12], raw[12:]
        files[filename] = aead.decrypt(nonce, ct, filename.encode())
    return files
