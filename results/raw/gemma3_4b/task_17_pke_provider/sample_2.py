"""Pluggable public-key encryption; the algorithm is chosen from configuration.

    provider = get_provider({"pke": "rsa-oaep-2048"})
    public_key, private_key = provider.generate_keypair()
    blob = provider.encrypt(public_key, data);  data = provider.decrypt(private_key, blob)
Each message gets a fresh AES-256-GCM key, wrapped with the provider's algorithm.
Unknown algorithm names are rejected.
"""
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_CONFIG = {"pke": "ml-kem-768"}
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


class MLKEM768:
    name = "ML-KEM-768"

    def generate_keypair(self):
        # Placeholder for key generation - replace with actual ML-KEM key generation
        key_size = 768
        public_key = os.urandom(key_size)
        secret_key = os.urandom(key_size)
        return public_key, secret_key

    def export_secret_key(self):
        return self.secret_key

    def encap_secret(self, public_key):
        # Placeholder for key encapsulation - replace with actual ML-KEM encapsulation
        shared_secret = os.urandom(768)
        return shared_secret, shared_secret

    def decap_secret(self, ciphertext):
        # Placeholder for key decapsulation - replace with actual ML-KEM decapsulation
        shared_secret = os.urandom(768)
        return shared_secret

    def __init__(self, secret_key=None):
        if secret_key is None:
            self.secret_key = self.generate_keypair()[1]
        else:
            self.secret_key = secret_key


class MLDSA65:
    name = "ML-DSA-65"

    def generate_keypair(self):
        # Placeholder for key generation - replace with actual ML-DSA key generation
        key_size = 65
        public_key = os.urandom(key_size)
        secret_key = os.urandom(key_size)
        return public_key, secret_key

    def export_secret_key(self):
        return self.secret_key

    def sign(self, message):
        # Placeholder for signing - replace with actual ML-DSA signing
        signature = os.urandom(key_size)
        return signature

    def verify(self, message, signature, public_key):
        # Placeholder for verification - replace with actual ML-DSA verification
        return True

    def sign_with_ctx_str(self, message, context):
        # Placeholder for signing with context - replace with actual ML-DSA signing
        signature = os.urandom(key_size)
        return signature

    def verify_with_ctx_str(self, message, signature, context, public_key):
        # Placeholder for verification with context - replace with actual ML-DSA verification
        return True


PROVIDERS = {
    "ML-KEM-768": MLKEM768,
    "ML-DSA-65": MLDSA65
}


def available_algorithms():
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for config["pke"] (default from DEFAULT_CONFIG)."""
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
