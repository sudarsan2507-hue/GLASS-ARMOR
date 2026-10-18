"""Policy-driven message encryption: a policy string chooses the algorithms.

    policy = load_policy("kex=ecdh-p256; aead=aes-256-gcm")
    public_key, private_key = policy.generate_keypair()
    blob = policy.encrypt(public_key, data, aad);  data = policy.decrypt(private_key, blob, aad)
Encryption is ECIES-style: an ephemeral key agreement with the recipient's key, HKDF-SHA256
(bound to the policy and the ephemeral key), then the chosen AEAD.
blob = ephemeral public key (65, uncompressed point) | nonce (12) | ciphertext
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

DEFAULT_POLICY = "kex=ecdh-p256; aead=aes-256-gcm"
AEADS = {"aes-256-gcm": AESGCM, "chacha20-poly1305": ChaCha20Poly1305}
KEX = ("ecdh-p256",)
_PT = serialization.PublicFormat.UncompressedPoint


class Policy:
    def __init__(self, kex, aead):
        self.kex, self.aead = kex, aead

    def _key(self, shared_secret, context):
        info = f"pq-gate policy v1|{self.kex}|{self.aead}|".encode() + context
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)

    def generate_keypair(self):
        key = ec.generate_private_key(ec.SECP256R1())
        return (key.public_key().public_bytes(serialization.Encoding.X962, _PT),
                key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))

    def encrypt(self, public_key, data, aad=b""):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
        ephemeral = ec.generate_private_key(ec.SECP256R1())
        eph_public = ephemeral.public_key().public_bytes(serialization.Encoding.X962, _PT)
        key = self._key(ephemeral.exchange(ec.ECDH(), peer), eph_public)
        nonce = os.urandom(12)
        return eph_public + nonce + AEADS[self.aead](key).encrypt(nonce, data, aad)

    def decrypt(self, private_key, blob, aad=b""):
        eph_public, nonce, ciphertext = blob[:65], blob[65:77], blob[77:]
        me = serialization.load_der_private_key(private_key, password=None)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_public)
        key = self._key(me.exchange(ec.ECDH(), peer), eph_public)
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
    kex = settings.get("kex", "ecdh-p256")
    aead = settings.get("aead", "aes-256-gcm")
    if kex not in KEX or aead not in AEADS:
        raise ValueError(f"unsupported policy: kex={kex} aead={aead}")
    return Policy(kex, aead)

