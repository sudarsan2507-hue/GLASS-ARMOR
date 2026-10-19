"""End‑to‑end sealed chat messages ("sealed box" style, post‑quantum).

Each user has a long‑term ML‑KEM‑768 identity key. To send a message, the sender
encapsulates a random shared secret to the recipient’s public key, derives an
AES‑256‑GCM key with HKDF‑SHA256 (bound to the encapsulation ciphertext), and
encrypts a JSON payload containing the sender name and the message text.

sealed = 2‑byte ciphertext length | ciphertext | nonce (12) | ciphertext‑AESGCM
"""

import hashlib
import json
import os
import struct

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Helper
# --------------------------------------------------------------------------- #
def _message_key(shared_secret: bytes, context: bytes) -> bytes:
    """Derive a 32‑byte AES‑GCM key from a KEM shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate sealed message v1" + context,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
# Public API (kept compatible with the original X25519 version)
# --------------------------------------------------------------------------- #
def generate_identity():
    """Generate a long‑term ML‑KEM‑768 identity key pair.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        * ``public_key`` – raw public key bytes (to be shared)
        * ``private_key`` – raw secret key bytes (to be kept secret)
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key


def fingerprint(public_key: bytes) -> str:
    """Short human‑readable fingerprint for comparing identity keys."""
    digest = hashlib.sha256(public_key).hexdigest()[:20]
    return " ".join(digest[i : i + 4] for i in range(0, 20, 4))


def seal(recipient_public: bytes, sender: str, text: str) -> bytes:
    """Encrypt ``text`` from ``sender`` for the recipient.

    Parameters
    ----------
    recipient_public : bytes
        The recipient’s ML‑KEM‑768 public key.
    sender : str
        Human‑readable name of the sender (included in the clear‑text payload).
    text : str
        Message body.

    Returns
    -------
    bytes
        The sealed message: ``len(ciphertext)||ciphertext||nonce||aesgcm``.
    """
    # 1️⃣  Encapsulate a fresh shared secret for the recipient.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(recipient_public)

    # 2️⃣  Derive the symmetric encryption key.
    key = _message_key(shared_secret, ciphertext)

    # 3️⃣  Encrypt the JSON payload with AES‑256‑GCM.
    nonce = os.urandom(12)
    payload = json.dumps({"from": sender, "text": text}).encode()
    encrypted = AESGCM(key).encrypt(nonce, payload, None)

    # 4️⃣  Assemble the final sealed blob.
    #    Store the ciphertext length as a 2‑byte big‑endian integer so the
    #    receiver knows where the KEM part ends.
    ct_len = struct.pack(">H", len(ciphertext))
    return ct_len + ciphertext + nonce + encrypted


def open_sealed(private_key: bytes, sealed: bytes):
    """Decrypt a sealed message.

    Parameters
    ----------
    private_key : bytes
        The recipient’s ML‑KEM‑768 secret key.
    sealed : bytes
        The sealed message produced by :func:`seal`.

    Returns
    -------
    (sender, text) : tuple[str, str]

    Raises
    ------
    ValueError
        If the sealed blob is malformed or decryption fails.
    """
    # Minimum size: 2‑byte length + at least 1‑byte ciphertext + 12‑byte nonce + 16‑byte tag
    if len(sealed) < 2 + 1 + 12 + 16:
        raise ValueError("message too short")

    # 1️⃣  Extract components.
    ct_len = struct.unpack(">H", sealed[:2])[0]
    expected_min = 2 + ct_len + 12 + 16
    if len(sealed) < expected_min:
        raise ValueError("message truncated")

    ciphertext = sealed[2 : 2 + ct_len]
    nonce = sealed[2 + ct_len : 2 + ct_len + 12]
    encrypted = sealed[2 + ct_len + 12 :]

    # 2️⃣  Decapsulate to obtain the shared secret.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(ciphertext)

    # 3️⃣  Derive the same symmetric key.
    key = _message_key(shared_secret, ciphertext)

    # 4️⃣  Decrypt the payload.
    try:
        payload = AESGCM(key).decrypt(nonce, encrypted, None)
    except Exception as exc:
        raise ValueError("decryption failed or message tampered with") from exc

    data = json.loads(payload)
    return data["from"], data["text"]
