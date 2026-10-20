"""Policy-driven message encryption: a policy string chooses the algorithms.

    policy = load_policy("kex=ml-kem-768; aead=aes-256-gcm")
    public_key, private_key = policy.generate_keypair()
    blob = policy.encrypt(public_key, data, aad);  data = policy.decrypt(private_key, blob, aad)
Encryption is ML-KEM-style: an ephemeral key agreement with the recipient's key, HKDF-SHA256
(bound to the policy and the ephemeral key), then the chosen AEAD.
blob = ephemeral public key (96, uncompressed point) | nonce (12) | ciphertext
"""
import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

DEFAULT_POLICY = "kex=ml-kem-768; aead=aes-256-gcm"
AEADS = {"aes-256-gcm": AESGCM}
KEX = ("ml-kem-768",)
_PT = serialization.PublicFormat.UncompressedPoint


class Policy:
    def __init__(self, kex, aead):
        self.kex, self.aead = kex, aead

    def _key(self, shared_secret, context):
        info = f"pq-gate policy v1|{self.kex}|{self.aead}|".encode() + context
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)

    def generate_keypair(self):
        kem = oqs.KeyEncapsulation(self.kex)
        public_key = kem.generate_keypair()  # bytes
        secret_key = kem.export_secret_key()  # bytes
        return (public_key, secret_key)

    def encrypt(self, public_key, data, aad=b""):
        kem = oqs.KeyEncapsulation(self.kex)
        kem2 = oqs.KeyEncapsulation(self.kex, secret_key=kem.export_secret_key())
        ciphertext, shared_secret = kem.encap_secret(public_key)
        key = self._key(shared_secret, public_key)
        nonce = os.urandom(12)
        return ciphertext + nonce + AEADS[self.aead](key).encrypt(nonce, data, aad)

    def decrypt(self, private_key, blob, aad=b""):
        kem = oqs.KeyEncapsulation(self.kex, secret_key=private_key)
        ciphertext, nonce, ciphertext = blob[:96], blob[96:108], blob[108:]
        shared_secret = kem.decap_secret(ciphertext)
        key = self._key(shared_secret, public_key)
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
    aead = settings.get("aead", "aes-256-gcm")
    if kex not in KEX or aead not in AEADS:
        raise ValueError(f"unsupported policy: kex={kex} aead={aead}")
    return Policy(kex, aead)
