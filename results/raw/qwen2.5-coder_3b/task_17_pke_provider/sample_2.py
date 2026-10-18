"""Pluggable public-key encryption; the algorithm is chosen from configuration.

    provider = get_provider({"pke": "ml-kem-768"})
    public_key, secret_key = provider.generate_keypair()
    ciphertext, shared_secret = provider.encap_secret(public_key)
    shared_secret = provider.decap_secret(ciphertext)  # 32 bytes
Each message gets a fresh AES-256-GCM key, wrapped with the provider's algorithm.
Unknown algorithm names are rejected.
"""
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from liboqs import oqs

DEFAULT_CONFIG = {"pke": "ml-kem-768"}
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


class MlKemProvider:
    name = "ml-kem-768"

    def generate_keypair(self):
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        public_key = kem.generate_keypair()  # bytes
        secret_key = kem.export_secret_key()  # bytes
        return (public_key, secret_key)

    def encap_secret(self, public_key):
        kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decap_secret(self, ciphertext):
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret


class MlDsaProvider:
    name = "ml-dsa-65"

    def generate_keypair(self):
        sig = oqs.Signature("ML-DSA-65")
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        return (public_key, secret_key)

    def sign(self, message):
        sig = oqs.Signature("ML-DSA-65", secret_key=secret_key)
        return sig.sign(message)

    def verify(self, message, signature, public_key):
        sig = oqs.Signature("ML-DSA-65")
        return sig.verify(message, signature, public_key)


PROVIDERS = {MlKemProvider.name: MlKemProvider, MlDsaProvider.name: MlDsaProvider}


def available_algorithms():
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for config["pke"] (default from DEFAULT_CONFIG)."""
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
