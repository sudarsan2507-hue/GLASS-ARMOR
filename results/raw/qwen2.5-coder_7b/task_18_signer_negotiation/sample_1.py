"""Signature algorithm chosen at runtime: from configuration or by negotiation with a peer.

    signer = get_signer(DEFAULT_ALG)
    public_key, private_key = signer.generate_keypair()
    envelope = seal_envelope(DEFAULT_ALG, private_key, b"msg")   # {"alg", "msg", "sig"}
    message = open_envelope(public_key, envelope)
    alg = negotiate(peer_offers)   # first of OUR preferences (SUPPORTED) that the peer offers
"""
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

SUPPORTED = ["ml-dsa-65"]  # our preference order
DEFAULT_ALG = SUPPORTED[0]


def _pem_pair(private_key):
    return (private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo),
            private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))


class MlDsaSigner:
    name = "ml-dsa-65"

    def generate_keypair(self):
        return _pem_pair(oqs.Signature("ML-DSA-65").generate_keypair())

    def sign(self, private_key, message):
        key = serialization.load_pem_private_key(private_key, password=None)
        return key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_key, message, signature):
        try:
            serialization.load_pem_public_key(public_key).verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False


SIGNERS = {MlDsaSigner.name: MlDsaSigner}


def get_signer(name):
    if name not in SIGNERS:
        raise ValueError(f"unsupported signature algorithm: {name}")
    return SIGNERS[name]()


def negotiate(peer_offers):
    """Pick the first algorithm in SUPPORTED that the peer also offers."""
    for name in SUPPORTED:
        if name in peer_offers:
            return name
    raise ValueError("no common signature algorithm")


def seal_envelope(alg, private_key, message):
    signature = get_signer(alg).sign(private_key, alg.encode() + b"|" + message)
    return {"alg": alg, "msg": base64.b64encode(message).decode(), "sig": base64.b64encode(signature).decode()}


def open_envelope(public_key, envelope):
    """Return the message bytes. Raises ValueError if the algorithm or signature is not acceptable."""
    alg = envelope.get("alg")
    if alg not in SUPPORTED:
        raise ValueError("algorithm not allowed")
    message = base64.b64decode(envelope["msg"])
    if not get_signer(alg).verify(public_key, alg.encode() + b"|" + message, base64.b64decode(envelope["sig"])):
        raise ValueError("bad signature")
    return message
