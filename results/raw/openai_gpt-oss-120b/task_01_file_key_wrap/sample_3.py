"""Encrypted file storage with per‑file data keys (envelope encryption).

Each file is encrypted with a fresh random AES‑256‑GCM data key. The data key is
wrapped with the owner's post‑quantum ML‑KEM‑768 public key and stored next to the
ciphertext. The filename is bound to the ciphertext as associated data.

Blob layout: 2‑byte wrapped‑key length | wrapped key | 12‑byte nonce |
ciphertext
"""
import os
import struct

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
#  Key‑pair generation (ML‑KEM‑768)
# --------------------------------------------------------------------------- #
def generate_keypair():
    """Return (public_key, private_key) as bytes for a file owner.

    The keys are generated with the post‑quantum KEM *ML‑KEM‑768*.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key


# --------------------------------------------------------------------------- #
#  Key wrapping / unwrapping (KEM + symmetric encryption)
# --------------------------------------------------------------------------- #
def _derive_kek(shared_secret: bytes) -> bytes:
    """Derive a 256‑bit key‑encryption‑key from a KEM shared secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq‑envelope‑wrap",
    )
    return hkdf.derive(shared_secret)


def wrap_key(public_key: bytes, data_key: bytes) -> bytes:
    """Wrap a data key for the owner of ``public_key`` using ML‑KEM‑768.

    The returned bytes contain:
        2‑byte length of the KEM ciphertext |
        KEM ciphertext |
        12‑byte AES‑GCM nonce |
        AES‑GCM ciphertext (data_key || tag)
    """
    # 1. KEM encapsulation
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    kem_ct, shared_secret = kem.encap_secret(public_key)

    # 2. Derive a symmetric KEK from the shared secret
    kek = _derive_kek(shared_secret)

    # 3. Encrypt the data key with the KEK (AES‑GCM, no AAD)
    nonce = os.urandom(12)
    enc_data_key = AESGCM(kek).encrypt(nonce, data_key, None)

    # 4. Pack everything
    wrapped = (
        struct.pack(">H", len(kem_ct)) +  # length of KEM ciphertext
        kem_ct +
        nonce +
        enc_data_key
    )
    return wrapped


def unwrap_key(private_key: bytes, wrapped: bytes) -> bytes:
    """Recover a data key with the owner's private key.

    ``wrapped`` must be the value produced by :func:`wrap_key`.
    """
    # 1. Extract components
    kem_ct_len = struct.unpack(">H", wrapped[:2])[0]
    offset = 2
    kem_ct = wrapped[offset : offset + kem_ct_len]
    offset += kem_ct_len
    nonce = wrapped[offset : offset + 12]
    offset += 12
    enc_data_key = wrapped[offset:]

    # 2. KEM decapsulation
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(kem_ct)

    # 3. Derive the same KEK
    kek = _derive_kek(shared_secret)

    # 4. Decrypt the data key
    data_key = AESGCM(kek).decrypt(nonce, enc_data_key, None)
    return data_key


# --------------------------------------------------------------------------- #
#  File encryption / decryption (envelope encryption)
# --------------------------------------------------------------------------- #
def encrypt_file(public_key: bytes, plaintext: bytes, filename: str = "") -> bytes:
    """Encrypt file contents for the owner of ``public_key``."""
    # Random AES‑256‑GCM data key
    data_key = AESGCM.generate_key(bit_length=256)

    # Encrypt the payload (filename bound as AAD)
    payload_nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(
        payload_nonce, plaintext, filename.encode()
    )

    # Wrap the data key with the recipient's KEM public key
    wrapped = wrap_key(public_key, data_key)

    # Blob: length of wrapped key | wrapped key | payload nonce | ciphertext
    return struct.pack(">H", len(wrapped)) + wrapped + payload_nonce + ciphertext


def decrypt_file(private_key: bytes, blob: bytes, filename: str = "") -> bytes:
    """Decrypt a blob made by :func:`encrypt_file`.

    Raises if the key, blob or filename is wrong.
    """
    # Extract wrapped key
    (wrapped_len,) = struct.unpack(">H", blob[:2])
    wrapped = blob[2 : 2 + wrapped_len]

    # Extract payload nonce and ciphertext
    payload_nonce = blob[2 + wrapped_len : 14 + wrapped_len]
    ciphertext = blob[14 + wrapped_len :]

    # Recover the data key
    data_key = unwrap_key(private_key, wrapped)

    # Decrypt the payload
    return AESGCM(data_key).decrypt(payload_nonce, ciphertext, filename.encode())


# --------------------------------------------------------------------------- #
#  Convenience helpers for file I/O
# --------------------------------------------------------------------------- #
def save_encrypted(path: str, public_key: bytes, plaintext: bytes) -> None:
    """Encrypt ``plaintext`` and write it to ``path`` (filename bound as AAD)."""
    blob = encrypt_file(public_key, plaintext, os.path.basename(path))
    with open(path, "wb") as f:
        f.write(blob)


def load_encrypted(path: str, private_key: bytes) -> bytes:
    """Read and decrypt a file written by :func:`save_encrypted`."""
    with open(path, "rb") as f:
        blob = f.read()
    return decrypt_file(private_key, blob, os.path.basename(path))
