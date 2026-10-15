"""Signature algorithm chosen at runtime: from configuration or by negotiation with a peer.

    signer = get_signer(DEFAULT_ALG)
    public_key, private_key = signer.generate_keypair()
    envelope = seal_envelope(DEFAULT_ALG, private_key, b"msg")   # {"alg", "msg", "sig"}
    message = open_envelope(public_key, envelope)
    alg = negotiate(peer_offers)   # first of OUR preferences (SUPPORTED) that the peer offers
"""
import base64
import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from liboqs import KeyEncapsulation, OQS

SUPPORTED = ["ecdsa-p256", "rsa-pss-2048"]  # our preference order
DEFAULT_ALG = SUPPORTED[0]


def _pem_pair(private_key):
    return (private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo),
            private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))


class EcdsaSigner:
    name = "ecdsa-p256"

    def generate_keypair(self):
        return _pem_pair(ec.generate_private_key(ec.SECP256R1()))

    def sign(self, private_key, message):
        key = serialization.load_pem_private_key(private_key, password=None)
        return key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_key, message, signature):
        try:
            serialization.load_pem_public_key(public_key).verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False


class RsaPssSigner:
    name = "rsa-pss-2048"
    _pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

    def generate_keypair(self):
        return _pem_pair(rsa.generate_private_key(public_exponent=65537, key_size=2048))

    def sign(self, private_key, message):
        key = serialization.load_pem_private_key(private_key, password=None)
        return key.sign(message, self._pss, hashes.SHA256())

    def verify(self, public_key, message, signature):
        try:
            serialization.load_pem_public_key(public_key).verify(signature, message, self._pss, hashes.SHA256())
            return True
        except (InvalidSignature, ValueError):
            return False


SIGNERS = {EcdsaSigner.name: EcdsaSigner, RsaPssSigner.name: RsaPssSigner}


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


def main():
    # Example Usage (Illustrative - Replace with your actual setup)
    # This example demonstrates the basic usage of the signers.
    # It does not implement the full ML-KEM/DSA flow.

    # Generate a random keypair for ECDSA
    ecdsa_signer = EcdsaSigner()
    ecdsa_public_key, ecdsa_private_key = ecdsa_signer.generate_keypair()

    # Generate a random keypair for RSA-PSS
    rsa_signer = RsaPssSigner()
    rsa_public_key, rsa_private_key = rsa_signer.generate_keypair()

    # Sign a message with ECDSA
    message = b"This is a test message."
    ecdsa_signature = ecdsa_signer.sign(ecdsa_private_key, message)
    print(f"ECDSA Signature: {ecdsa_signature}")

    # Verify the ECDSA signature
    ecdsa_signer.verify(ecdsa_public_key, message, ecdsa_signature)

    # Sign a message with RSA-PSS
    rsa_signature = rsa_signer.sign(rsa_private_key, message)
    print(f"RSA-PSS Signature: {rsa_signature}")

    # Verify the RSA-PSS signature
    rsa_signer.verify(rsa_public_key, message, rsa_signature)


if __name__ == "__main__":
    main()
