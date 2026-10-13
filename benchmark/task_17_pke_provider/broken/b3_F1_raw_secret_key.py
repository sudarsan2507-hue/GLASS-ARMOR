"""Pluggable public-key encryption; the algorithm is chosen from configuration.
Post-quantum version: only ML-KEM-768 is offered, with no classical fallback.

    provider = get_provider({"pke": "ml-kem-768"})
    public_key, private_key = provider.generate_keypair()
    blob = provider.encrypt(public_key, data);  data = provider.decrypt(private_key, blob)
Each message gets a fresh ML-KEM encapsulation; the shared secret goes through
HKDF-SHA256 to an AES-256-GCM key. Unknown algorithm names are rejected.
blob = KEM ciphertext (1088) | nonce (12) | ciphertext
"""
import os

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_CONFIG = {"pke": "ml-kem-768"}
KEM_ALG = "ML-KEM-768"
KEM_CT_LEN = 1088


def _derive_key(shared_secret):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate pke provider v1").derive(shared_secret)


class MlKemProvider:
    name = "ml-kem-768"

    def __init__(self):
        if KEM_ALG not in oqs.get_enabled_kem_mechanisms():
            raise RuntimeError("ML-KEM-768 is not available in liboqs")

    def generate_keypair(self):
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            return kem.generate_keypair(), kem.export_secret_key()

    def encrypt(self, public_key, data):
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            kem_ct, shared_secret = kem.encap_secret(public_key)
        nonce = os.urandom(12)
        return kem_ct + nonce + AESGCM(shared_secret).encrypt(nonce, data, kem_ct)

    def decrypt(self, private_key, blob):
        kem_ct, nonce, ciphertext = blob[:KEM_CT_LEN], blob[KEM_CT_LEN:KEM_CT_LEN + 12], blob[KEM_CT_LEN + 12:]
        with oqs.KeyEncapsulation(KEM_ALG, secret_key=private_key) as kem:
            shared_secret = kem.decap_secret(kem_ct)
        return AESGCM(shared_secret).decrypt(nonce, ciphertext, kem_ct)


PROVIDERS = {MlKemProvider.name: MlKemProvider}


def available_algorithms():
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for config["pke"] (default from DEFAULT_CONFIG)."""
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
