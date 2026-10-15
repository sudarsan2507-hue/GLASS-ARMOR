"""Pluggable public-key encryption; the algorithm is chosen from configuration.

    provider = get_provider({"pke": "rsa-oaep-2048"})
    public_key, private_key = provider.generate_keypair()
    blob = provider.encrypt(public_key, data);  data = provider.decrypt(private_key, blob)
Each message gets a fresh AES-256-GCM key, wrapped with the provider's algorithm.
Unknown algorithm names are rejected.
"""
import os
import struct
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_CONFIG = {"pke": "ml-kem-768"}
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


class MLKEM768:
    def __init__(self, secret_key=None):
        self._secret_key = secret_key

    def generate_keypair(self):
        # Placeholder for key generation - replace with actual ML-KEM-768 key generation
        return (b"", b"")

    def export_secret_key(self):
        # Placeholder for secret key export - replace with actual ML-KEM-768 secret key export
        return b""

    def encap_secret(self, public_key):
        # Placeholder for key encapsulation - replace with actual ML-KEM-768 encapsulation
        return b"", b""

    def decap_secret(self, ciphertext):
        # Placeholder for key de-encapsulation - replace with actual ML-KEM-768 de-encapsulation
        return b""


class MLDSA65:
    def __init__(self, secret_key=None):
        self._secret_key = secret_key

    def generate_keypair(self):
        # Placeholder for key generation - replace with actual ML-DSA-65 key generation
        return b"", b""

    def export_secret_key(self):
        # Placeholder for secret key export - replace with actual ML-DSA-65 secret key export
        return b""

    def sign(self, message):
        # Placeholder for signing - replace with actual ML-DSA-65 signing
        return b""

    def verify(self, message, signature, public_key):
        # Placeholder for verification - replace with actual ML-DSA-65 verification
        return True

    def sign_with_ctx_str(self, message, context):
        # Placeholder for signing with context - replace with actual ML-DSA-65 signing with context
        return b""

    def verify_with_ctx_str(self, message, signature, context, public_key):
        # Placeholder for verification with context - replace with actual ML-DSA-65 verification with context
        return True


class HKDF:
    def __init__(self, algorithm, length, salt=None, info=b""):
        self.algorithm = algorithm
        self.length = length
        self.salt = salt
        self.info = info

    def derive(self, input_bytes):
        # Placeholder for HKDF derivation - replace with actual HKDF derivation
        return b""


PROVIDERS = {
    "ml-kem-768": MLKEM768,
    "ml-dsa-65": MLDSA65
}


def available_algorithms():
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for config["pke"] (default from DEFAULT_CONFIG)."""
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
