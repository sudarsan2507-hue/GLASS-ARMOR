"""Key encapsulation algorithm chosen at runtime: from configuration or by negotiation with a peer.

    kem = get_kem(DEFAULT_ALG)
    public_key, secret_key = kem.generate_keypair()
    ciphertext, shared_secret = seal_envelope(DEFAULT_ALG, public_key, b"msg")   # {"alg", "msg", "ciphertext"}
    message = open_envelope(public_key, secret_key, ciphertext)
    alg = negotiate(peer_offers)   # first of OUR preferences (SUPPORTED) that the peer offers
"""
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

SUPPORTED = ["ml-kem-768", "ml-dsa-65"]  # our preference order
DEFAULT_ALG = SUPPORTED[0]


def _pem_pair(private_key):
    return (private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo),
            private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))


class MlKem768:
    name = "ml-kem-768"

    def generate_keypair(self):
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        public_key = kem.generate_keypair()  # bytes
        secret_key = kem.export_secret_key()  # bytes
        kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
        ciphertext, shared_secret = kem2.encap_secret(public_key)
        return public_key, shared_secret

    def decap_secret(self, ciphertext):
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        return kem.decap_secret(ciphertext)  # 32 bytes


class MlDsa65:
    name = "ml-dsa-65"

    def generate_keypair(self):
        sig = oqs.Signature("ML-DSA-65")
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        signature = sig.sign_with_ctx_str(b"msg", context)
        ok = sig.verify_with_ctx_str(b"msg", signature, context, public_key)
        return public_key, secret_key

    def sign(self, message):
        sig = oqs.Signature("ML-DSA-65")
        return sig.sign(message)

    def verify(self, message, signature, public_key):
        ok = sig.verify(message, signature, public_key)
        return ok


KEMS = {MlKem768.name: MlKem768, MlDsa65.name: MlDsa65}


def get_kem(name):
    if name not in KEMS:
        raise ValueError(f"unsupported key encapsulation algorithm: {name}")
    return KEMS[name]()


def negotiate(peer_offers):
    """Pick the first algorithm in SUPPORTED that the peer also offers."""
    for name in SUPPORTED:
        if name in peer_offers:
            return name
    raise ValueError("no common key encapsulation algorithm")


def seal_envelope(alg, public_key, message):
    kem = get_kem(alg)
    public_key_bytes = public_key.encode()
    secret_key_bytes = kem.generate_keypair()[1]
    kem = oqs.KeyEncapsulation(alg, secret_key=secret_key_bytes)
    ciphertext, shared_secret = kem.encap_secret(public_key_bytes)
    return {"alg": alg, "msg": base64.b64encode(message).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}


def open_envelope(public_key, secret_key, ciphertext):
    """Return the message bytes. Raises ValueError if the algorithm or ciphertext is not acceptable."""
    alg = ciphertext.get("alg")
    if alg not in SUPPORTED:
        raise ValueError("algorithm not allowed")
    ciphertext_bytes = base64.b64decode(ciphertext["ciphertext"])
    kem = oqs.KeyEncapsulation(alg, secret_key=secret_key)
    shared_secret = kem.decap_secret(ciphertext_bytes)
    return shared_secret
