"""End‑to‑end sealed chat messages using a post‑quantum KEM (ML‑KEM‑768).

Each user has a long‑term ML‑KEM‑768 key pair. To send a message, the sender
encapsulates a shared secret to the recipient’s public key, derives an
AES‑256‑GCM key with HKDF‑SHA256 (bound to the KEM ciphertext), and encrypts
the payload. The sealed message format is:

    ciphertext (ML‑KEM‑768) | nonce (12) | ciphertext‑AESGCM

The public API (generate_identity, fingerprint, seal, open_sealed) is kept
identical to the original X25519 implementation so existing tests continue
to pass.
"""

import hashlib
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Constants for the chosen algorithm
# --------------------------------------------------------------------------- #
_KEM_ALG = "ML-KEM-768"
# For ML‑KEM‑768 the ciphertext size is 1088 bytes (public spec)
_KEM_CIPHERTEXT_LEN = 1088
# The shared secret produced by the KEM is 32 bytes (matches AES‑256‑GCM key)
_SHARED_SECRET_LEN = 32

# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _message_key(shared_secret: bytes, context: bytes) -> bytes:
    """
    Derive a 32‑byte AES‑GCM key from the KEM shared secret and a context.
    The context binds the key to the particular encapsulation (ciphertext).
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate sealed message v1" + context,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
# Public API – unchanged signatures
# --------------------------------------------------------------------------- #
def generate_identity():
    """
    Generate a long‑term ML‑KEM‑768 identity key pair.

    Returns
    -------
    (public_key_bytes, private_key_bytes)
        Both are raw byte strings suitable for storage or transmission.
    """
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key


def fingerprint(public_key: bytes) -> str:
    """
    Produce a short, human‑readable fingerprint for a public key.
    """
    digest = hashlib.sha256(public_key).hexdigest()[:20]
    return " ".join(digest[i : i + 4] for i in range(0, 20, 4))


def seal(recipient_public: bytes, sender: str, text: str) -> bytes:
    """
    Encrypt ``text`` from ``sender`` for the recipient identified by
    ``recipient_public``.  The returned bytes are:

        ciphertext | nonce | aes‑gcm‑ciphertext

    where ``ciphertext`` is the ML‑KEM‑768 encapsulation.
    """
    # 1️⃣  Encapsulate a shared secret to the recipient’s public key.
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    ciphertext, shared_secret = kem.encap_secret(recipient_public)

    # 2️⃣  Derive the symmetric AES‑GCM key, binding it to the encapsulation.
    key = _message_key(shared_secret, ciphertext)

    # 3️⃣  Encrypt the JSON payload.
    nonce = os.urandom(12)
    payload = json.dumps({"from": sender, "text": text}).encode()
    encrypted = AESGCM(key).encrypt(nonce, payload, None)

    # 4️⃣  Assemble the sealed message.
    return ciphertext + nonce + encrypted


def open_sealed(private_key: bytes, sealed: bytes):
    """
    Decrypt a sealed message produced by :func:`seal`.

    Parameters
    ----------
    private_key : bytes
        The recipient’s ML‑KEM‑768 secret key (raw bytes).
    sealed : bytes
        The sealed message as returned by :func:`seal`.

    Returns
    -------
    (sender: str, text: str)

    Raises
    ------
    ValueError
        If the message is malformed or authentication fails.
    """
    # Verify minimal length (ciphertext + nonce + at least a GCM tag)
    min_len = _KEM_CIPHERTEXT_LEN + 12 + 16
    if len(sealed) < min_len:
        raise ValueError("message too short")

    # Split the sealed blob.
    ciphertext = sealed[:_KEM_CIPHERTEXT_LEN]
    nonce = sealed[_KEM_CIPHERTEXT_LEN : _KEM_CIPHERTEXT_LEN + 12]
    aes_ciphertext = sealed[_KEM_CIPHERTEXT_LEN + 12 :]

    # 1️⃣  Decapsulate to recover the shared secret.
    kem = oqs.KeyEncapsulation(_KEM_ALG, secret_key=private_key)
    shared_secret = kem.decap_secret(ciphertext)

    # 2️⃣  Derive the same AES‑GCM key.
    key = _message_key(shared_secret, ciphertext)

    # 3️⃣  Decrypt and parse the payload.
    payload = json.loads(AESGCM(key).decrypt(nonce, aes_ciphertext, None))
    return payload["from"], payload["text"]
