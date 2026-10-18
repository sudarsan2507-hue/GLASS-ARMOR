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
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from oqs import KeyEncapsulation, Signature

DEFAULT_CONFIG = {"pke": "ml-kem-768"}
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


class MlKemProvider:
    name = "ml-kem-768"

    def generate_keypair(self):
        kem = KeyEncapsulation("ML-KEM-768")
        public_key = kem.generate_keypair()  # bytes
        secret_key = kem.export_secret_key()  # bytes
        kem2 = KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        shared_secret = kem2.decap_secret(ciphertext)  # 32 bytes
        return (public_key, secret_key)

    def encrypt(self, public_key, data):
        data_key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
        wrapped = serialization.load_pem_public_key(public_key).encrypt(data_key, _OAEP)
        return struct.pack(">H", len(wrapped)) + wrapped + nonce + AESGCM(data_key).encrypt(nonce, data, None)

    def decrypt(self, private_key, blob):
        (n,) = struct.unpack(">H", blob[:2])
        wrapped, nonce, ciphertext = blob[2:2 + n], blob[2 + n:14 + n], blob[14 + n:]
        data_key = serialization.load_pem_private_key(private_key, password=None).decrypt(wrapped, _OAEP)
        return AESGCM(data_key).decrypt(nonce, ciphertext, None)


class MlDsaProvider:
    name = "ml-dsa-65"

    def generate_keypair(self):
        sig = Signature("ML-DSA-65")
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        signature = sig.sign(message)
        ok = sig.verify(message, signature, public_key)  # bool
        signature = sig.sign_with_ctx_str(message, context)
        ok = sig.verify_with_ctx_str(message, signature, context, public_key)
        return (public_key, secret_key)

    def sign(self, message):
        sig = Signature("ML-DSA-65")
        return sig.sign(message)

    def verify(self, message, signature, public_key):
        sig = Signature("ML-DSA-65")
        return sig.verify(message, signature, public_key)

    def sign_with_ctx_str(self, message, context):
        sig = Signature("ML-DSA-65")
        return sig.sign_with_ctx_str(message, context)

    def verify_with_ctx_str(self, message, signature, context, public_key):
        sig = Signature("ML-DSA-65")
        return sig.verify_with_ctx_str(message, signature, context, public_key)


PROVIDERS = {MlKemProvider.name: MlKemProvider, MlDsaProvider.name: MlDsaProvider}


def available_algorithms():
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for config["pke"] (default from DEFAULT_CONFIG)."""
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
