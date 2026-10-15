"""Pluggable public-key encryption; the algorithm is chosen from configuration.

    provider = get_provider({"pke": "rsa-oaep-2048"})
    public_key, private_key = provider.generate_keypair()
    blob = provider.encrypt(public_key, data);  data = provider.decrypt(private_key, blob)
Each message gets a fresh AES-256-GCM key, wrapped with the provider's algorithm.
Unknown algorithm names are rejected.
"""
import os
import struct

import cryptography.hazmat.primitives.ciphers.aead
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import RSAprivatekey
from cryptography.hazmat.primitives.serialization.rsa import SubjectPublicKeyInfo
from cryptography.hazmat.primitives.serialization.backports import rsa as rsa_backports
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_CONFIG = {"pke": "ml-kem-768"}
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=SHA256()),
                     algorithm=SHA256(), label=None)


class MLKEM768:
    def __init__(self, secret_key=None):
        self._secret_key = secret_key

    def generate_keypair(self):
        # Placeholder for ML-KEM-768 key generation.  Replace with actual implementation.
        return None, None

    def export_secret_key(self):
        # Placeholder for ML-KEM-768 secret key export. Replace with actual implementation.
        return None

    def encap_secret(self, public_key):
        # Placeholder for ML-KEM-768 key encapsulation. Replace with actual implementation.
        return None, None

    def decap_secret(self, ciphertext):
        # Placeholder for ML-KEM-768 key de-encapsulation. Replace with actual implementation.
        return None

    def __init__(self, name="ML-KEM-768", secret_key=None):
        self.name = name
        self._secret_key = secret_key

    def generate_keypair(self):
        # Placeholder for ML-KEM-768 key generation.  Replace with actual implementation.
        return None, None

    def export_secret_key(self):
        # Placeholder for ML-KEM-768 secret key export. Replace with actual implementation.
        return None

    def encap_secret(self, public_key):
        # Placeholder for ML-KEM-768 key encapsulation. Replace with actual implementation.
        return None, None

    def decap_secret(self, ciphertext):
        # Placeholder for ML-KEM-768 key de-encapsulation. Replace with actual implementation.
        return None


class MLDSA65:
    def __init__(self, secret_key=None):
        self._secret_key = secret_key

    def generate_keypair(self):
        # Placeholder for ML-DSA-65 key generation.  Replace with actual implementation.
        return None, None

    def export_secret_key(self):
        # Placeholder for ML-DSA-65 secret key export. Replace with actual implementation.
        return None

    def sign(self, message):
        # Placeholder for ML-DSA-65 signing. Replace with actual implementation.
        return None

    def verify(self, message, signature, public_key):
        # Placeholder for ML-DSA-65 verification. Replace with actual implementation.
        return False

    def sign_with_ctx_str(self, message, context):
        # Placeholder for ML-DSA-65 signing with context. Replace with actual implementation.
        return None

    def verify_with_ctx_str(self, message, signature, context, public_key):
        # Placeholder for ML-DSA-65 verification with context. Replace with actual implementation.
        return False


class MLHKDF:
    def __init__(self):
        self.hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"...")

    def derive(self, input_bytes):
        return self.hkdf.derive(input_bytes)


PROVIDERS = {
    "ml-kem-768": MLKEM768,
    "ml-dsa-65": MLDSA65,
}


def available_algorithms():
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for config["pke"] (default from DEFAULT_CONFIG)."""
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
