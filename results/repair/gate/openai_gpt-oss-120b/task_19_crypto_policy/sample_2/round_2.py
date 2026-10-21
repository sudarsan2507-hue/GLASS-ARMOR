"""
Post‑quantum cryptography utilities using liboqs.

This module provides a thin wrapper around liboqs key‑encapsulation mechanisms
(ML‑KEM‑768) and symmetric AEAD ciphers (AES‑GCM, ChaCha20‑Poly1305).  The public
API mirrors the original classical‑cryptography implementation so that existing
tests continue to work unchanged.

Key‑exchange identifiers, AEAD algorithms and policy parsing are defined below.
"""

# --------------------------------------------------------------------------- #
# Imports
# --------------------------------------------------------------------------- #
import os
from typing import Tuple

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Constants & helpers
# --------------------------------------------------------------------------- #
DEFAULT_POLICY = "kex=ml-kem-768; aead=aes-256-gcm"

# AEAD algorithms supported by the original code
AEADS = {
    "aes-256-gcm": AESGCM,
    "chacha20-poly1305": ChaCha20Poly1305,
}

# Supported key‑exchange identifiers (post‑quantum only)
KEX = ("ml-kem-768",)

# Length of the ML‑KEM‑768 ciphertext (public‑key encapsulation output)
_KEM_CT_LEN = {"ml-kem-768": 1088}


# --------------------------------------------------------------------------- #
# Policy implementation
# --------------------------------------------------------------------------- #
class Policy:
    """
    Holds the chosen key‑exchange and AEAD algorithm.  The public methods
    ``generate_keypair``, ``encrypt`` and ``decrypt`` keep the same signatures
    as the original implementation.
    """

    def __init__(self, kex: str, aead: str):
        self.kex = kex
        self.aead = aead

    # --------------------------------------------------------------------- #
    # Internal helpers
    # --------------------------------------------------------------------- #
    def _hkdf_derive(self, shared_secret: bytes, context: bytes) -> bytes:
        """
        Derive a 32‑byte symmetric key from the shared secret using HKDF‑SHA256.
        The ``info`` field is bound to the policy and the caller‑provided
        ``context`` (the encapsulation data).
        """
        info = (
            f"pq-gate policy v1|{self.kex}|{self.aead}|".encode()
            + context
        )
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        ).derive(shared_secret)

    # --------------------------------------------------------------------- #
    # Public API
    # --------------------------------------------------------------------- #
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a (public_key, private_key) pair for the selected
        post‑quantum key‑exchange algorithm.

        * **ML‑KEM‑768** returns the raw public and secret key bytes produced by
          liboqs.
        """
        if self.kex == "ml-kem-768":
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            pub_bytes = kem.generate_keypair()
            sec_bytes = kem.export_secret_key()
            return pub_bytes, sec_bytes

        raise ValueError(f"Unsupported KEX algorithm: {self.kex}")

    def encrypt(self, public_key: bytes, data: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt ``data`` for the holder of ``public_key``.  The returned blob
        contains the encapsulation data, a random nonce and the AEAD ciphertext.
        """
        aead_cls = AEADS[self.aead]

        if self.kex == "ml-kem-768":
            # ----- post‑quantum ML‑KEM‑768 path -----
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            kem_ct, shared = kem.encap_secret(public_key)
            key = self._hkdf_derive(shared, kem_ct)
            nonce = os.urandom(12)
            ct = aead_cls(key).encrypt(nonce, data, aad)
            return kem_ct + nonce + ct

        raise ValueError(f"Unsupported KEX algorithm: {self.kex}")

    def decrypt(self, private_key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt`.  Returns the original plaintext.
        """
        aead_cls = AEADS[self.aead]

        if self.kex == "ml-kem-768":
            # ----- post‑quantum ML‑KEM‑768 path -----
            ct_len = _KEM_CT_LEN[self.kex]
            kem_ct = blob[:ct_len]
            nonce = blob[ct_len : ct_len + 12]
            ct = blob[ct_len + 12 :]

            kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
            shared = kem.decap_secret(kem_ct)
            key = self._hkdf_derive(shared, kem_ct)
            return aead_cls(key).decrypt(nonce, ct, aad)

        raise ValueError(f"Unsupported KEX algorithm: {self.kex}")


# --------------------------------------------------------------------------- #
# Policy parsing
# --------------------------------------------------------------------------- #
def load_policy(text: str) -> Policy:
    """
    Parse a policy string of the form ``"name=value; name=value"``.
    Raises ``ValueError`` for unknown or missing settings.
    """
    settings = {}
    for item in text.split(";"):
        if item.strip():
            name, sep, value = item.partition("=")
            if not sep:
                raise ValueError(f"bad policy item: {item!r}")
            settings[name.strip()] = value.strip()

    kex = settings.get("kex", "ml-kem-768")
    aead = settings.get("aead", "aes-256-gcm")

    if kex not in KEX:
        raise ValueError(f"unsupported KEX algorithm: {kex}")
    if aead not in AEADS:
        raise ValueError(f"unsupported AEAD algorithm: {aead}")

    return Policy(kex, aead)
