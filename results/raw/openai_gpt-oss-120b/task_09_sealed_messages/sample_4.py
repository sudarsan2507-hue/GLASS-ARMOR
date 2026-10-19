"""End‑to‑end sealed chat messages ("sealed box" style, post‑quantum).

Each user now has a long‑term ML‑KEM‑768 key pair. To send a message the sender
encapsulates a shared secret to the recipient’s public key, derives an
AES‑256‑GCM key with HKDF‑SHA256 (bound to the encapsulation and the recipient’s
public key), and encrypts a JSON payload that contains the sender name and the
message text.

The sealed format is:

    2‑byte big‑endian ciphertext length |
    ciphertext (ML‑KEM encapsulation) |
    2‑byte big‑endian recipient‑public‑key length |
    recipient public key (raw bytes) |
    12‑byte nonce |
    AES‑GCM ciphertext (includes tag)

All public functions keep the same signatures as the original X25519‑based
implementation so existing tests continue to work.
"""

import json
import os
import hashlib

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Helper – derive the symmetric message key from the shared secret.
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
# Identity handling (ML‑KEM‑768)
# --------------------------------------------------------------------------- #
_KEM_ALG = "ML-KEM-768"


def generate_identity():
    """
    Generate a long‑term post‑quantum identity.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        * ``public_key`` – raw public key bytes (to be shared)
        * ``private_key`` – raw secret key bytes (to be kept secret)
    """
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key


def fingerprint(public_key: bytes) -> str:
    """
    Short human‑readable fingerprint for comparing identity keys.

    Parameters
    ----------
    public_key : bytes
        Raw public key bytes.

    Returns
    -------
    str
        20‑character hexadecimal fingerprint split into groups of four.
    """
    digest = hashlib.sha256(public_key).hexdigest()[:20]
    return " ".join(digest[i : i + 4] for i in range(0, 20, 4))


# --------------------------------------------------------------------------- #
# Sealing / opening
# --------------------------------------------------------------------------- #
def seal(recipient_public: bytes, sender: str, text: str) -> bytes:
    """
    Encrypt ``text`` from ``sender`` for the recipient.

    Parameters
    ----------
    recipient_public : bytes
        Recipient's ML‑KEM‑768 public key (raw bytes).
    sender : str
        Human‑readable identifier of the sender (will be placed in the payload).
    text : str
        Message body.

    Returns
    -------
    bytes
        The sealed message, ready to be transmitted.
    """
    # 1️⃣  Encapsulate a shared secret to the recipient.
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    ciphertext, shared_secret = kem.encap_secret(recipient_public)

    # 2️⃣  Derive the AES‑GCM key.  The context binds the ciphertext and the
    #     recipient's public key together, preventing replay across recipients.
    key = _message_key(shared_secret, ciphertext + recipient_public)

    # 3️⃣  Build the encrypted payload.
    nonce = os.urandom(12)
    payload = json.dumps({"from": sender, "text": text}).encode()
    encrypted = AESGCM(key).encrypt(nonce, payload, None)

    # 4️⃣  Serialize the sealed message.
    #    • 2‑byte length of the KEM ciphertext
    #    • KEM ciphertext
    #    • 2‑byte length of the recipient public key (constant but kept explicit)
    #    • recipient public key
    #    • 12‑byte nonce
    #    • AES‑GCM ciphertext (includes 16‑byte tag)
    ct_len = len(ciphertext).to_bytes(2, "big")
    pk_len = len(recipient_public).to_bytes(2, "big")
    return ct_len + ciphertext + pk_len + recipient_public + nonce + encrypted


def open_sealed(private_key: bytes, sealed: bytes) -> tuple[str, str]:
    """
    Decrypt a sealed message.

    Parameters
    ----------
    private_key : bytes
        Recipient's ML‑KEM‑768 secret key (raw bytes).
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
    # Minimum size: 2 (ct_len) + 2 (pk_len) + 12 (nonce) + 16 (GCM tag)
    if len(sealed) < 2 + 2 + 12 + 16:
        raise ValueError("sealed message too short")

    # 1️⃣  Parse lengths.
    ct_len = int.from_bytes(sealed[:2], "big")
    offset = 2
    if len(sealed) < offset + ct_len + 2:
        raise ValueError("sealed message truncated (ciphertext)")

    ciphertext = sealed[offset : offset + ct_len]
    offset += ct_len

    pk_len = int.from_bytes(sealed[offset : offset + 2], "big")
    offset += 2
    if len(sealed) < offset + pk_len + 12 + 16:
        raise ValueError("sealed message truncated (public key / payload)")

    recipient_public = sealed[offset : offset + pk_len]
    offset += pk_len

    nonce = sealed[offset : offset + 12]
    offset += 12
    encrypted = sealed[offset:]

    # 2️⃣  Decapsulate to obtain the shared secret.
    kem = oqs.KeyEncapsulation(_KEM_ALG, secret_key=private_key)
    shared_secret = kem.decap_secret(ciphertext)

    # 3️⃣  Derive the same AES‑GCM key the sender used.
    key = _message_key(shared_secret, ciphertext + recipient_public)

    # 4️⃣  Decrypt the payload.
    try:
        payload = AESGCM(key).decrypt(nonce, encrypted, None)
    except Exception as exc:
        raise ValueError("decryption failed or message tampered with") from exc

    data = json.loads(payload)
    return data["from"], data["text"]
