"""End‑to‑end sealed chat messages ("sealed box" style, post‑quantum).

Each user has a long‑term ML‑KEM‑768 identity key. To send a message, the sender
encapsulates a shared secret to the recipient’s public key, derives an
AES‑256‑GCM key with HKDF‑SHA256 (bound to the encapsulation ciphertext), and
encrypts a JSON payload containing the sender name and the message text.

sealed = 2‑byte ciphertext length | ciphertext | nonce (12) | ciphertext

The public API (generate_identity, fingerprint, seal, open_sealed) is unchanged
so existing tests continue to work.
"""

import hashlib
import json
import os
import struct

import oqs
from cryptography.hazmat.primitives import hashes
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
# Public API
# --------------------------------------------------------------------------- #
def generate_identity():
    """Return a tuple *(public_key, private_key)* as raw bytes.

    The keys are generated with the ML‑KEM‑768 algorithm.  The private key
    contains everything needed for decapsulation (it is the exact byte string
    returned by ``KeyEncapsulation.export_secret_key()``).
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    private_key = kem.export_secret_key()        # bytes
    return public_key, private_key


def fingerprint(public_key: bytes) -> str:
    """Short human‑readable fingerprint for comparing identity keys."""
    digest = hashlib.sha256(public_key).hexdigest()[:20]
    return " ".join(digest[i : i + 4] for i in range(0, 20, 4))


def seal(recipient_public: bytes, sender: str, text: str) -> bytes:
    """Encrypt ``text`` from ``sender`` for the recipient.

    Returns the sealed message as bytes.  The format is:

        2‑byte big‑endian length of the KEM ciphertext
        KEM ciphertext (ML‑KEM‑768 encapsulation)
        12‑byte AES‑GCM nonce
        AES‑GCM ciphertext (includes the 16‑byte tag)
    """
    # 1️⃣  Encapsulate a shared secret to the recipient's public key.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(recipient_public)

    # 2️⃣  Derive the symmetric encryption key.
    key = _message_key(shared_secret, ciphertext + recipient_public)

    # 3️⃣  Encrypt the JSON payload.
    nonce = os.urandom(12)
    payload = json.dumps({"from": sender, "text": text}).encode()
    encrypted = AESGCM(key).encrypt(nonce, payload, None)

    # 4️⃣  Assemble the sealed message.
    sealed = (
        struct.pack(">H", len(ciphertext))  # 2‑byte length prefix
        + ciphertext
        + nonce
        + encrypted
    )
    return sealed


def open_sealed(private_key: bytes, sealed: bytes):
    """Decrypt a sealed message.

    Returns a tuple ``(sender, text)``.  Raises ``ValueError`` if the message is
    malformed or decryption fails.
    """
    # Minimum size: 2‑byte length + at least 1‑byte ciphertext + 12‑byte nonce + 16‑byte tag
    if len(sealed) < 2 + 1 + 12 + 16:
        raise ValueError("message too short")

    # 1️⃣  Extract the KEM ciphertext.
    ct_len = struct.unpack(">H", sealed[:2])[0]
    expected_min = 2 + ct_len + 12 + 16
    if len(sealed) < expected_min:
        raise ValueError("message truncated")

    offset = 2
    kem_ct = sealed[offset : offset + ct_len]
    offset += ct_len
    nonce = sealed[offset : offset + 12]
    offset += 12
    aes_ct = sealed[offset:]

    # 2️⃣  Decapsulate to obtain the shared secret.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared_secret = kem.decap_secret(kem_ct)

    # 3️⃣  Derive the symmetric key (need our own public key for the context).
    my_public = kem.export_public_key()
    key = _message_key(shared_secret, kem_ct + my_public)

    # 4️⃣  Decrypt the payload.
    payload = json.loads(AESGCM(key).decrypt(nonce, aes_ct, None))
    return payload["from"], payload["text"]
