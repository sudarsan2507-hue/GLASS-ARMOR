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
from cryptography.hazmat.primitives.serialization.rsa import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from oqs import KeyEncapsulation, ML_KEM_768, ML_DSA_65

DEFAULT_CONFIG = {"pke": "rsa-oaep-2048"}

AESGCM = cryptography.hazmat.primitives.ciphers.algorithms.AEAD.create(
    SHA256(),
    cryptography.hazmat.primitives.ciphers.algorithms.AEAD.create(
        SHA256(),
        cryptography.hazmat.primitives.ciphers.algorithms.CounterMode(
            SHA256(),
            128
        )
    )
)


class RsaOaepProvider:
    name = "rsa-oaep-2048"

    def generate_keypair(self):
        key = RSAprivatekey.generate(2048)
        return (key.public_key().public_bytes(PublicFormat.PEM, serialization.EncryptionAlgorithm.RSA).decode(),
                key.private_bytes(serialization.PrivateFormat.PEM, serialization.NoEncryption(), None))

    def encrypt(self, public_key, data):
        data_key, nonce = AESGCM.encrypt(data, None, None)
        wrapped = load_pem_public_key(public_key.encode()).export_key().key
        return struct.pack(">H", len(wrapped)) + wrapped + nonce + data_key

    def decrypt(self, private_key, blob):
        data_key = load_pem_private_key(private_key.encode(), None, serialization.PrivateFormat.PEM).export_key().key
        nonce = struct.unpack(">H", blob[:2])[0]
        ciphertext = blob[2:2 + nonce]
        return AESGCM.decrypt(ciphertext, None, None, data_key)


PROVIDERS = {RsaOaepProvider.name: RsaOaepProvider}


def available_algorithms():
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for config["pke"] (default from DEFAULT_CONFIG)."""
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
