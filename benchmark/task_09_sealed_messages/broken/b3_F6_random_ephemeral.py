"""End-to-end sealed chat messages ("sealed box" style). Post-quantum version.

Identity keys are hybrid: X25519 + ML-KEM-768. To send a message, the sender makes an
ephemeral X25519 key (ECDH with the recipient's X25519 key) and encapsulates to the
recipient's ML-KEM key. HKDF-SHA256 over both shared secrets, bound to the ephemeral key,
the KEM ciphertext and the recipient's X25519 key, gives the AES-256-GCM message key.
The sender's name travels inside the ciphertext.

public_key  = X25519 public (32) | ML-KEM public (1184)
private_key = X25519 private (32) | ML-KEM secret key
sealed      = ephemeral X25519 public (32) | KEM ciphertext (1088) | nonce (12) | ciphertext
"""
import hashlib
import json
import os
import random

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALG = "ML-KEM-768"
X_LEN, KEM_CT_LEN = 32, 1088
_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _message_key(classical_secret, pq_secret, context):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate hybrid sealed message v1" + context).derive(classical_secret + pq_secret)


def generate_identity():
    """Return (public_key, private_key) as bytes."""
    x_private = X25519PrivateKey.generate()
    x_private_bytes = x_private.private_bytes(serialization.Encoding.Raw,
                                              serialization.PrivateFormat.Raw,
                                              serialization.NoEncryption())
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_public = kem.generate_keypair()
        kem_secret = kem.export_secret_key()
    return x_private.public_key().public_bytes(*_RAW) + kem_public, x_private_bytes + kem_secret


def fingerprint(public_key):
    """Short human-readable fingerprint for comparing identity keys."""
    digest = hashlib.sha256(public_key).hexdigest()[:20]
    return " ".join(digest[i:i + 4] for i in range(0, 20, 4))


def seal(recipient_public, sender, text):
    """Encrypt `text` from `sender` for the recipient. Returns sealed bytes."""
    recipient_x, recipient_kem = recipient_public[:X_LEN], recipient_public[X_LEN:]
    ephemeral = X25519PrivateKey.from_private_bytes(random.randbytes(32))
    eph_public = ephemeral.public_key().public_bytes(*_RAW)
    classical = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_x))
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_ct, pq = kem.encap_secret(recipient_kem)
    key = _message_key(classical, pq, eph_public + kem_ct + recipient_x)
    nonce = os.urandom(12)
    payload = json.dumps({"from": sender, "text": text}).encode()
    return eph_public + kem_ct + nonce + AESGCM(key).encrypt(nonce, payload, None)


def open_sealed(private_key, sealed):
    """Return (sender, text). Raises if the message is not for us or was tampered with."""
    if len(sealed) < X_LEN + KEM_CT_LEN + 12 + 16:
        raise ValueError("message too short")
    eph_public = sealed[:X_LEN]
    kem_ct = sealed[X_LEN:X_LEN + KEM_CT_LEN]
    nonce = sealed[X_LEN + KEM_CT_LEN:X_LEN + KEM_CT_LEN + 12]
    ciphertext = sealed[X_LEN + KEM_CT_LEN + 12:]
    me = X25519PrivateKey.from_private_bytes(private_key[:X_LEN])
    classical = me.exchange(X25519PublicKey.from_public_bytes(eph_public))
    with oqs.KeyEncapsulation(KEM_ALG, secret_key=private_key[X_LEN:]) as kem:
        pq = kem.decap_secret(kem_ct)
    my_x = me.public_key().public_bytes(*_RAW)
    key = _message_key(classical, pq, eph_public + kem_ct + my_x)
    payload = json.loads(AESGCM(key).decrypt(nonce, ciphertext, None))
    return payload["from"], payload["text"]
