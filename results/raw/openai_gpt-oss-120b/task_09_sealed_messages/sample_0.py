"""End‑to‑end sealed chat messages ("sealed box" style, post‑quantum).

Each user has a long‑term ML‑KEM‑768 identity key. To send a message, the sender
encapsulates a shared secret to the recipient’s public key, derives an
AES‑256‑GCM key with HKDF‑SHA256 (bound to the ciphertext and the recipient’s
public key), and encrypts a JSON payload that contains the sender’s name and
the message text.

sealed = ciphertext (1088) | nonce (12) | ciphertext‑AESGCM
"""

import hashlib
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
_KEM_NAME = "ML-KEM-768"
# Size of a ciphertext produced by ML‑KEM‑768 (see liboqs documentation)
_CIPHERTEXT_SIZE = 1088  # bytes
_NONCE_SIZE = 12  # AES‑GCM nonce size
_AES_KEY_SIZE = 32  # 256‑bit key for AES‑GCM

# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _message_key(shared_secret: bytes, context: bytes) -> bytes:
    """
    Derive the AES‑GCM key from the KEM shared secret.

    The ``context`` binds the key to the particular encapsulation (ciphertext)
    and the recipient’s public key, mirroring the original X25519 design.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_SIZE,
        salt=None,
        info=b"pq-gate sealed message v1" + context,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
# Public API (unchanged signatures)
# --------------------------------------------------------------------------- #
def generate_identity():
    """
    Generate a long‑term ML‑KEM‑768 identity key pair.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        ``public_key`` – raw bytes that can be shared with peers.
        ``private_key`` – raw secret‑key bytes that must be kept confidential.
    """
    kem = oqs.KeyEncapsulation(_KEM_NAME)
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key


def fingerprint(public_key: bytes) -> str:
    """
    Short human‑readable fingerprint for comparing identity keys.

    Parameters
    ----------
    public_key : bytes
        The raw public key bytes.

    Returns
    -------
    str
        A 20‑character hexadecimal fingerprint split into groups of four.
    """
    digest = hashlib.sha256(public_key).hexdigest()[:20]
    return " ".join(digest[i : i + 4] for i in range(0, 20, 4))


def seal(recipient_public: bytes, sender: str, text: str) -> bytes:
    """
    Encrypt ``text`` from ``sender`` for the recipient.

    Parameters
    ----------
    recipient_public : bytes
        The recipient’s ML‑KEM‑768 public key.
    sender : str
        Human‑readable identifier of the sender (included in the clear‑text
        payload after decryption).
    text : str
        Message body.

    Returns
    -------
    bytes
        The sealed message: ``ciphertext || nonce || aesgcm‑ciphertext``.
    """
    # 1️⃣  Encapsulate a shared secret to the recipient.
    kem = oqs.KeyEncapsulation(_KEM_NAME)
    ciphertext, shared_secret = kem.encap_secret(recipient_public)

    # 2️⃣  Derive the symmetric AES‑GCM key.
    key = _message_key(shared_secret, ciphertext + recipient_public)

    # 3️⃣  Encrypt the JSON payload.
    nonce = os.urandom(_NONCE_SIZE)
    payload = json.dumps({"from": sender, "text": text}).encode()
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, payload, None)

    # 4️⃣  Assemble the sealed message.
    return ciphertext + nonce + encrypted


def open_sealed(private_key: bytes, sealed: bytes):
    """
    Decrypt a sealed message.

    Parameters
    ----------
    private_key : bytes
        The recipient’s ML‑KEM‑768 secret key.
    sealed : bytes
        The sealed message produced by :func:`seal`.

    Returns
    -------
    (sender, text) : tuple[str, str]
        The sender identifier and the original message text.

    Raises
    ------
    ValueError
        If the sealed message is malformed or decryption fails.
    """
    # Basic length sanity check.
    min_len = _CIPHERTEXT_SIZE + _NONCE_SIZE + 16  # 16‑byte GCM tag minimum
    if len(sealed) < min_len:
        raise ValueError("message too short")

    # Split the sealed blob.
    ciphertext = sealed[:_CIPHERTEXT_SIZE]
    nonce = sealed[_CIPHERTEXT_SIZE : _CIPHERTEXT_SIZE + _NONCE_SIZE]
    encrypted = sealed[_CIPHERTEXT_SIZE + _NONCE_SIZE :]

    # Decapsulate to obtain the shared secret.
    kem = oqs.KeyEncapsulation(_KEM_NAME, secret_key=private_key)
    shared_secret = kem.decap_secret(ciphertext)

    # Derive the same AES‑GCM key the sender used.
    key = _message_key(shared_secret, ciphertext + kem.public_key())

    # Decrypt the payload.
    aesgcm = AESGCM(key)
    try:
        payload = aesgcm.decrypt(nonce, encrypted, None)
    except Exception as exc:
        raise ValueError("decryption failed or message tampered with") from exc

    # Parse JSON.
    try:
        data = json.loads(payload)
        return data["from"], data["text"]
    except Exception as exc:
        raise ValueError("invalid payload") from exc
