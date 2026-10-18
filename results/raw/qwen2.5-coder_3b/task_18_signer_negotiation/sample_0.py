"""Key encapsulation algorithm chosen at runtime: from configuration or by negotiation with a peer.

    kemp = get_kemp(DEFAULT_ALG)
    public_key, secret_key = kemp.generate_keypair()
    ciphertext, shared_secret = seal_envelope(DEFAULT_ALG, public_key, b"msg")   # {"alg", "msg", "ciphertext"}
    message = open_envelope(public_key, secret_key, ciphertext)
    alg = negotiate(peer_offers)   # first of OUR preferences (SUPPORTED) that the peer offers
"""
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

SUPPORTED = ["ml-kem-768"]  # our preference order
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
        public_key = kem.generate_keypair()            # bytes
        secret_key = kem.export_secret_key()           # bytes
        kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
        ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
        shared_secret = kem2.decap_secret(ciphertext)  # 32 bytes
        return public_key, secret_key

    def seal(self, public_key, message):
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return {"alg": self.name, "msg": base64.b64encode(message).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}

    def open(self, secret_key, ciphertext):
        kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret


KEMS = {MlKem768.name: MlKem768}


def get_kemp(name):
    if name not in KEMS:
        raise ValueError(f"unsupported key encapsulation algorithm: {name}")
    return KEMS[name]()


def negotiate(peer_offers):
    """Pick the first algorithm in SUPPORTED that the peer also offers."""
    for name in SUPPORTED:
        if name in peer_offers:
            return name
    raise ValueError("no common key encapsulation algorithm")
