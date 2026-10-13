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

DEFAULT_CONFIG = {"pke": "rsa-oaep-2048"}
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


class RsaOaepProvider:
    name = "rsa-oaep-2048"

    def generate_keypair(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return (key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo),
                key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))

    def encrypt(self, public_key, data):
        data_key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
        wrapped = serialization.load_pem_public_key(public_key).encrypt(data_key, _OAEP)
        return struct.pack(">H", len(wrapped)) + wrapped + nonce + AESGCM(data_key).encrypt(nonce, data, None)

    def decrypt(self, private_key, blob):
        (n,) = struct.unpack(">H", blob[:2])
        wrapped, nonce, ciphertext = blob[2:2 + n], blob[2 + n:14 + n], blob[14 + n:]
        data_key = serialization.load_pem_private_key(private_key, password=None).decrypt(wrapped, _OAEP)
        return AESGCM(data_key).decrypt(nonce, ciphertext, None)


PROVIDERS = {RsaOaepProvider.name: RsaOaepProvider}


def available_algorithms():
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for config["pke"] (default from DEFAULT_CONFIG)."""
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
