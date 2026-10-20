"""Pluggable public-key encryption; the algorithm is chosen from configuration.

    provider = get_provider({"pke": "ml-kem-768"})
    public_key, private_key = provider.generate_keypair()
    blob = provider.encrypt(public_key, data);  data = provider.decrypt(private_key, blob)
Each message gets a fresh AES-256-GCM key, wrapped with the provider's algorithm.
Unknown algorithm names are rejected.
"""
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import oqs

DEFAULT_CONFIG = {"pke": "ml-kem-768"}


class MlKem768Provider:
    name = "ml-kem-768"

    def generate_keypair(self):
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return (public_key, secret_key)

    def encrypt(self, public_key, data):
        data_key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
        wrapped = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
        return struct.pack(">H", len(wrapped)) + wrapped + nonce + AESGCM(data_key).encrypt(nonce, data, None)

    def decrypt(self, private_key, blob):
        (n,) = struct.unpack(">H", blob[:2])
        wrapped, nonce, ciphertext = blob[2:2 + n], blob[2 + n:14 + n], blob[14 + n:]
        kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
        data_key = kem2.decap_secret(wrapped)
        return AESGCM(data_key).decrypt(nonce, ciphertext, None)


PROVIDERS = {MlKem768Provider.name: MlKem768Provider}


def available_algorithms():
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for config["pke"] (default from DEFAULT_CONFIG)."""
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
