"""Policy-driven message encryption: a policy string chooses the algorithms.
Post-quantum version: the only key exchange is ML-KEM-768 (no classical fallback).

    policy = load_policy("kex=ml-kem-768; aead=aes-256-gcm")
    public_key, private_key = policy.generate_keypair()
    blob = policy.encrypt(public_key, data, aad);  data = policy.decrypt(private_key, blob, aad)
Encryption: ML-KEM-768 encapsulation to the recipient's key, HKDF-SHA256 (bound to the
policy and the KEM ciphertext), then the chosen AEAD.
blob = KEM ciphertext (1088) | nonce (12) | ciphertext
"""
import os

import oqs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_POLICY = "kex=x25519,ml-kem-768; aead=aes-256-gcm"  # first supported wins
AEADS = {"aes-256-gcm": AESGCM, "chacha20-poly1305": ChaCha20Poly1305}
KEX = ("x25519", "ml-kem-768")
KEM_ALG = "ML-KEM-768"
KEM_CT_LEN = 1088


class Policy:
    def __init__(self, kex, aead):
        self.kex, self.aead = kex, aead

    def _key(self, shared_secret, context):
        info = f"pq-gate policy v1|{self.kex}|{self.aead}|".encode() + context
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)

    def generate_keypair(self):
        if self.kex == "x25519":
            key = X25519PrivateKey.generate()
            return (key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                    key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption()))
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            return kem.generate_keypair(), kem.export_secret_key()

    def encrypt(self, public_key, data, aad=b""):
        if self.kex == "x25519":
            ephemeral = X25519PrivateKey.generate()
            eph_public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            key = self._key(ephemeral.exchange(X25519PublicKey.from_public_bytes(public_key)), eph_public)
            nonce = os.urandom(12)
            return eph_public + nonce + AEADS[self.aead](key).encrypt(nonce, data, aad)
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            kem_ct, shared_secret = kem.encap_secret(public_key)
        key = self._key(shared_secret, kem_ct)
        nonce = os.urandom(12)
        return kem_ct + nonce + AEADS[self.aead](key).encrypt(nonce, data, aad)

    def decrypt(self, private_key, blob, aad=b""):
        if self.kex == "x25519":
            eph_public, nonce, ciphertext = blob[:32], blob[32:44], blob[44:]
            shared = X25519PrivateKey.from_private_bytes(private_key).exchange(
                X25519PublicKey.from_public_bytes(eph_public))
            return AEADS[self.aead](self._key(shared, eph_public)).decrypt(nonce, ciphertext, aad)
        kem_ct, nonce, ciphertext = blob[:KEM_CT_LEN], blob[KEM_CT_LEN:KEM_CT_LEN + 12], blob[KEM_CT_LEN + 12:]
        with oqs.KeyEncapsulation(KEM_ALG, secret_key=private_key) as kem:
            shared_secret = kem.decap_secret(kem_ct)
        key = self._key(shared_secret, kem_ct)
        return AEADS[self.aead](key).decrypt(nonce, ciphertext, aad)


def load_policy(text):
    """Parse "name=value; name=value". Raises ValueError for unknown or missing settings."""
    settings = {}
    for item in text.split(";"):
        if item.strip():
            name, sep, value = item.partition("=")
            if not sep:
                raise ValueError(f"bad policy item: {item!r}")
            settings[name.strip()] = value.strip()
    kex = settings.get("kex", "ml-kem-768")
    kex = next((k.strip() for k in kex.split(",") if k.strip() in KEX), kex)
    aead = settings.get("aead", "aes-256-gcm")
    if kex not in KEX or aead not in AEADS:
        raise ValueError(f"unsupported policy: kex={kex} aead={aead}")
    return Policy(kex, aead)
