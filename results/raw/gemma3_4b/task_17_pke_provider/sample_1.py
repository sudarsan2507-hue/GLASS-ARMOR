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
        key = oqs.KeyEncapsulation("ML-KEM-768")
        public_key = key.generate_keypair()
        secret_key = key.export_secret_key()
        return public_key, secret_key

    def encap_secret(self, public_key):
        key = oqs.KeyEncapsulation("ML-KEM-768")
        ciphertext, shared_secret = key.encap_secret(public_key)
        return ciphertext, shared_secret

    def decaps_secret(self, ciphertext):
        key = oqs.KeyEncapsulation("ML-KEM-768")
        shared_secret = key.decap_secret(ciphertext)
        return shared_secret

    def export_secret_key(self):
        key = oqs.KeyEncapsulation("ML-KEM-768")
        return key.export_secret_key()


class MLDSA65:
    name = "ML-DSA-65"

    def generate_keypair(self):
        key = oqs.Signature("ML-DSA-65")
        public_key = key.generate_keypair()
        secret_key = key.export_secret_key()
        return public_key, secret_key

    def sign(self, message):
        key = oqs.Signature("ML-DSA-65")
        signature = key.sign(message)
        return signature

    def verify(self, message, signature, public_key):
        key = oqs.Signature("ML-DSA-65")
        ok = key.verify(message, signature, public_key)
        return ok

    def sign_with_ctx_str(self, message, context):
        key = oqs.Signature("ML-DSA-65")
        signature = key.sign_with_ctx_str(message, context)
        return signature

    def verify_with_ctx_str(self, message, signature, context, public_key):
        key = oqs.Signature("ML-DSA-65")
        ok = key.verify_with_ctx_str(message, signature, context, public_key)
        return ok


# ML-KEM-768
kem = MLKEM768()
# ML-DSA-65
sig = MLDSA65()
# HKDF (cryptography)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_CONFIG = {"pke": "ml-kem-768"}
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


class MLKEM768:
    name = "ML-KEM-768"

    def generate_keypair(self):
        key = oqs.KeyEncapsulation("ML-KEM-768")
        public_key = key.generate_keypair()
        secret_key = key.export_secret_key()
        return public_key, secret_key

    def encap_secret(self, public_key):
        key = oqs.KeyEncapsulation("ML-KEM-768")
        ciphertext, shared_secret = key.encap_secret(public_key)
        return ciphertext, shared_secret

    def decaps_secret(self, ciphertext):
        key = oqs.KeyEncapsulation("ML-KEM-768")
        shared_secret = key.decap_secret(ciphertext)
        return shared_secret

    def export_secret_key(self):
        key = oqs.KeyEncapsulation("ML-KEM-768")
        return key.export_secret_key()


class MLDSA65:
    name = "ML-DSA-65"

    def generate_keypair(self):
        key = oqs.Signature("ML-DSA-65")
        public_key = key.generate_keypair()
        secret_key = key.export_secret_key()
        return public_key, secret_key

    def sign(self, message):
        key = oqs.Signature("ML-DSA-65")
        signature = key.sign(message)
        return signature

    def verify(self, message, signature, public_key):
        key = oqs.Signature("ML-DSA-65")
        ok = key.verify(message, signature, public_key)
        return ok

    def sign_with_ctx_str(self, message, context):
        key = oqs.Signature("ML-DSA-65")
        signature = key.sign_with_ctx_str(message, context)
        return signature

    def verify_with_ctx_str(self, message, signature, context, public_key):
        key = oqs.Signature("ML-DSA-65")
        ok = key.verify_with_ctx_str(message, signature, context, public_key)
        return ok


# ML-KEM-768
kem = MLKEM768()
# ML-DSA-65
sig = MLDSA65()
# HKDF (cryptography)
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"...").derive(input_bytes)
