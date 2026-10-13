"""Signature algorithm chosen at runtime: from configuration or by negotiation with a peer.
Post-quantum version: only ML-DSA-65 is supported, with no classical fallback.

    signer = get_signer(DEFAULT_ALG)
    public_key, private_key = signer.generate_keypair()
    envelope = seal_envelope(DEFAULT_ALG, private_key, b"msg")   # {"alg", "msg", "sig"}
    message = open_envelope(public_key, envelope)
    alg = negotiate(peer_offers)   # first of OUR preferences (SUPPORTED) that the peer offers
"""
import base64

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SUPPORTED = ["ml-dsa-65"]  # our preference order
DEFAULT_ALG = SUPPORTED[0]


class MlDsaSigner:
    name = "ml-dsa-65"
    _alg = "ML-DSA-65"
    _context = b"pq-gate signer v1"

    def generate_keypair(self):
        with oqs.Signature(self._alg) as sig:
            return sig.generate_keypair(), sig.export_secret_key()

    def sign(self, private_key, message):
        with oqs.Signature(self._alg, secret_key=private_key) as sig:
            return sig.sign_with_ctx_str(message, self._context)

    def verify(self, public_key, message, signature):
        try:
            with oqs.Signature(self._alg) as sig:
                return sig.verify_with_ctx_str(message, signature, self._context, public_key)
        except Exception:
            return False


class EcdsaSigner:
    name = "ecdsa-p256"

    def generate_keypair(self):
        key = ec.generate_private_key(ec.SECP256R1())
        return (key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo),
                key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))

    def sign(self, private_key, message):
        key = serialization.load_pem_private_key(private_key, password=None)
        return key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_key, message, signature):
        try:
            serialization.load_pem_public_key(public_key).verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


SIGNERS = {MlDsaSigner.name: MlDsaSigner,
           EcdsaSigner.name: EcdsaSigner}  # for services configured with ECDSA keys


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
