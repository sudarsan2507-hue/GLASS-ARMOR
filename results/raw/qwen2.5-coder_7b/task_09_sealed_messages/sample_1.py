"""End-to-end sealed chat messages ("sealed box" style, ML-KEM / ML-DSA).

Each user has a long-term ML-DSA identity key. To send a message, the sender makes an
ephemeral ML-KEM key, does ECDH with the recipient's identity key and derives an
AES-256-GCM key with HKDF-SHA256, bound to both public keys. The sender's name travels
inside the ciphertext, so only the recipient learns who sent it.

sealed = ephemeral public key (32) | nonce (12) | ciphertext
"""
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import oqs

_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _message_key(shared_secret, context):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate sealed message v1" + context).derive(shared_secret)


def generate_identity():
    """Return (public_key, private_key) as raw bytes."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()            # bytes
    secret_key = kem.export_secret_key()           # bytes
    return public_key, secret_key


def fingerprint(public_key):
    """Short human-readable fingerprint for comparing identity keys."""
    digest = hashlib.sha256(public_key).hexdigest()[:20]
    return " ".join(digest[i:i + 4] for i in range(0, 20, 4))


def seal(recipient_public, sender, text):
    """Encrypt `text` from `sender` for the recipient. Returns sealed bytes."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    eph_public, eph_secret = kem.generate_keypair()            # bytes
    shared = kem.decap_secret(eph_secret, recipient_public)
    key = _message_key(shared, eph_public + recipient_public)
    nonce = os.urandom(12)
    payload = json.dumps({"from": sender, "text": text}).encode()
    return eph_public + nonce + AESGCM(key).encrypt(nonce, payload, None)


def open_sealed(private_key, sealed):
    """Return (sender, text). Raises if the message is not for us or was tampered with."""
    if len(sealed) < 32 + 12 + 16:
        raise ValueError("message too short")
    eph_public, nonce, ciphertext = sealed[:32], sealed[32:44], sealed[44:]
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    shared = kem.decap_secret(eph_public, kem.public_key)
    key = _message_key(shared, eph_public + kem.public_key)
    payload = json.loads(AESGCM(key).decrypt(nonce, ciphertext, None))
    return payload["from"], payload["text"]
