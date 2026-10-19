"""Encrypted backup archives that several recipients can restore.

One random archive key encrypts every file (AES‑256‑GCM, fresh nonce per file,
file name as associated data). The archive key is wrapped separately for each
recipient with a post‑quantum KEM (ML‑KEM‑768), so any recipient can restore the
backup with their own private key.

Archive = JSON bytes:
    {"version": 1,
     "recipients": {name: wrapped_key},
     "files": {filename: nonce + ciphertext}}   (values base64)
"""
import base64
import json
import os
from struct import pack, unpack

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _b64(data: bytes) -> str:
    """Base‑64 encode bytes and return a UTF‑8 string."""
    return base64.b64encode(data).decode()


def _unb64(text: str) -> bytes:
    """Decode a base‑64 string back to bytes."""
    return base64.b64decode(text)


# --------------------------------------------------------------------------- #
# Key‑generation / wrapping primitives (post‑quantum)
# --------------------------------------------------------------------------- #
_KEM_NAME = "ML-KEM-768"
_KEM_CIPHER_LEN_SIZE = 2  # store KEM ciphertext length in two bytes (big‑endian)


def generate_keypair():
    """
    Return ``(public_key, private_key)`` as raw bytes for a recipient.

    The keys are generated with the post‑quantum KEM *ML‑KEM‑768* from liboqs.
    """
    kem = oqs.KeyEncapsulation(_KEM_NAME)
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


def _derive_kek(shared_secret: bytes) -> bytes:
    """
    Derive a 256‑bit key‑encryption‑key (KEK) from a KEM shared secret using HKDF‑SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"archive‑key‑wrap",
    )
    return hkdf.derive(shared_secret)


def _wrap_for(public_key: bytes, recipient: str, archive_key: bytes) -> bytes:
    """
    Wrap ``archive_key`` for ``recipient`` using the recipient's public KEM key.

    The returned bytes layout is:
        [2‑byte big‑endian length of KEM ciphertext][KEM ciphertext][AES‑GCM nonce][AES‑GCM ciphertext]
    """
    # 1️⃣  Perform KEM encapsulation
    kem = oqs.KeyEncapsulation(_KEM_NAME)
    kem_ct, shared_secret = kem.encap_secret(public_key)

    # 2️⃣  Derive a symmetric KEK from the shared secret
    kek = _derive_kek(shared_secret)

    # 3️⃣  Encrypt the archive key with AES‑GCM using the KEK
    nonce = os.urandom(12)
    aead = AESGCM(kek)
    enc_key = aead.encrypt(nonce, archive_key, None)  # no associated data

    # 4️⃣  Assemble the wrapped blob
    kem_len = pack(">H", len(kem_ct))          # 2‑byte length prefix
    return kem_len + kem_ct + nonce + enc_key


def _unwrap(private_key: bytes, recipient: str, wrapped: bytes) -> bytes:
    """
    Recover the original ``archive_key`` for ``recipient`` using the private KEM key.

    Expects the layout produced by ``_wrap_for``.
    """
    # 1️⃣  Split the wrapped blob
    kem_len = unpack(">H", wrapped[:_KEM_CIPHER_LEN_SIZE])[0]
    kem_ct = wrapped[_KEM_CIPHER_LEN_SIZE : _KEM_CIPHER_LEN_SIZE + kem_len]
    aes_part = wrapped[_KEM_CIPHER_LEN_SIZE + kem_len :]

    # 2️⃣  Decapsulate to obtain the shared secret
    kem = oqs.KeyEncapsulation(_KEM_NAME, secret_key=private_key)
    shared_secret = kem.decap_secret(kem_ct)

    # 3️⃣  Derive the same KEK
    kek = _derive_kek(shared_secret)

    # 4️⃣  Decrypt the archive key
    nonce = aes_part[:12]
    ct = aes_part[12:]
    aead = AESGCM(kek)
    return aead.decrypt(nonce, ct, None)


# --------------------------------------------------------------------------- #
# Public API (unchanged signatures)
# --------------------------------------------------------------------------- #
def create_archive(recipients, files):
    """
    ``recipients``: mapping ``{name: public_key_bytes}``
    ``files``:      mapping ``{filename: file_bytes}``

    Returns the complete archive as ``bytes`` (JSON, base‑64 encoded blobs).
    """
    # Random archive key for AES‑256‑GCM
    archive_key = AESGCM.generate_key(bit_length=256)
    aead = AESGCM(archive_key)

    # Encrypt each file (nonce ‑> ciphertext)
    enc_files = {}
    for filename, data in files.items():
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, data, filename.encode())
        enc_files[filename] = _b64(nonce + ct)

    # Wrap the archive key for every recipient
    wrapped = {
        name: _b64(_wrap_for(pk, name, archive_key))
        for name, pk in recipients.items()
    }

    return json.dumps(
        {"version": 1, "recipients": wrapped, "files": enc_files}
    ).encode()


def list_files(archive):
    """
    Return the file names stored in the archive (no key needed).
    """
    return sorted(json.loads(archive)["files"])


def restore_archive(archive, recipient, private_key):
    """
    Decrypt every file for ``recipient`` using their private KEM key.

    Raises ``KeyError`` for unknown recipients, other exceptions if the archive
    is tampered with.
    """
    doc = json.loads(archive)

    # Recover the archive key
    wrapped_blob = _unb64(doc["recipients"][recipient])
    archive_key = _unwrap(private_key, recipient, wrapped_blob)

    aead = AESGCM(archive_key)
    files = {}
    for filename, blob in doc["files"].items():
        raw = _unb64(blob)
        nonce, ct = raw[:12], raw[12:]
        files[filename] = aead.decrypt(nonce, ct, filename.encode())
    return files
