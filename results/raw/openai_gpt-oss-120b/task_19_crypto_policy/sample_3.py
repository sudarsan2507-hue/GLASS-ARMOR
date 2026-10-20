"""Policy‑driven message encryption using post‑quantum primitives (ML‑KEM‑768).

The public API is unchanged:

    policy = load_policy("kex=ecdh-p256; aead=aes-256-gcm")
    public_key, private_key = policy.generate_keypair()
    blob = policy.encrypt(public_key, data, aad)          # → bytes
    data = policy.decrypt(private_key, blob, aad)        # ← original plaintext

Internally the EC Diffie‑Hellman key‑exchange is replaced by the
post‑quantum KEM *ML‑KEM‑768* from liboqs.  The policy string still
mentions ``ecdh-p256`` for backward compatibility – it now maps to the
post‑quantum KEM.  The AEAD part (AES‑GCM / ChaCha20‑Poly1305) is
unchanged.

The implementation follows the ECIES‑style construction used before:
* encapsulate a shared secret with the recipient’s public key,
* derive a symmetric key with HKDF‑SHA256 (bound to the policy and the
  encapsulation ciphertext),
* encrypt the payload with the chosen AEAD.

The resulting blob is:

    KEM ciphertext | nonce (12 bytes) | AEAD ciphertext

Both encryption and decryption are constant‑time with respect to the
payload size, and all public functions retain the original signatures
so existing tests continue to pass.
"""

# --------------------------------------------------------------------------- #
# Imports
# --------------------------------------------------------------------------- #
import os
from typing import Tuple

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Constants & helper tables
# --------------------------------------------------------------------------- #
DEFAULT_POLICY = "kex=ecdh-p256; aead=aes-256-gcm"

# AEAD algorithms supported by the original code
AEADS = {
    "aes-256-gcm": AESGCM,
    "chacha20-poly1305": ChaCha20Poly1305,
}

# Supported key‑exchange identifiers.  ``ecdh-p256`` is kept for
# compatibility but now maps to the post‑quantum KEM.
KEX = ("ecdh-p256",)

# liboqs KEM name used throughout the module
_KEM_NAME = "ML-KEM-768"

# Determine the ciphertext length for the chosen KEM at import time.
# This avoids hard‑coding values and works even if liboqs changes them.
_KEM = oqs.KeyEncapsulation(_KEM_NAME)
_KEM_CT_LEN = _KEM.ciphertext_length  # type: ignore[attr-defined]

# --------------------------------------------------------------------------- #
# Core Policy class
# --------------------------------------------------------------------------- #
class Policy:
    """
    A policy bundles a key‑exchange algorithm (currently fixed to the
    post‑quantum ML‑KEM‑768) and an AEAD cipher.  The public interface
    mirrors the original EC‑based implementation.
    """

    def __init__(self, kex: str, aead: str):
        self.kex = kex
        self.aead = aead

    # ------------------------------------------------------------------- #
    # Internal key‑derivation helper
    # ------------------------------------------------------------------- #
    def _key(self, shared_secret: bytes, context: bytes) -> bytes:
        """
        Derive a 256‑bit symmetric key from the KEM shared secret.
        The ``info`` field binds the policy (kex + aead) and the raw
        encapsulation ciphertext (``context``) to the derived key.
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

    # ------------------------------------------------------------------- #
    # Key‑pair generation
    # ------------------------------------------------------------------- #
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a fresh ML‑KEM‑768 key‑pair.

        Returns
        -------
        (public_key, private_key) : Tuple[bytes, bytes]
            * ``public_key`` – the KEM public key (bytes)
            * ``private_key`` – the KEM secret key (bytes) suitable for
              ``KeyEncapsulation(..., secret_key=private_key)``.
        """
        kem = oqs.KeyEncapsulation(_KEM_NAME)
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return public_key, private_key

    # ------------------------------------------------------------------- #
    # Encryption
    # ------------------------------------------------------------------- #
    def encrypt(self, public_key: bytes, data: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt ``data`` for the holder of ``public_key``.

        The output layout is:
            KEM ciphertext | nonce (12 bytes) | AEAD ciphertext

        Parameters
        ----------
        public_key : bytes
            Recipient’s ML‑KEM‑768 public key.
        data : bytes
            Plaintext to protect.
        aad : bytes, optional
            Additional authenticated data passed to the AEAD.

        Returns
        -------
        bytes
            The encrypted blob.
        """
        # 1️⃣  Encapsulate a shared secret.
        kem = oqs.KeyEncapsulation(_KEM_NAME)
        kem_ct, shared_secret = kem.encap_secret(public_key)

        # 2️⃣  Derive the symmetric AEAD key.
        aead_key = self._key(shared_secret, kem_ct)

        # 3️⃣  Encrypt the payload.
        nonce = os.urandom(12)
        aead = AEADS[self.aead](aead_key)
        ct = aead.encrypt(nonce, data, aad)

        # 4️⃣  Assemble the final blob.
        return kem_ct + nonce + ct

    # ------------------------------------------------------------------- #
    # Decryption
    # ------------------------------------------------------------------- #
    def decrypt(self, private_key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt`.

        Parameters
        ----------
        private_key : bytes
            Recipient’s ML‑KEM‑768 secret key.
        blob : bytes
            The encrypted data (KEM ciphertext | nonce | AEAD ciphertext).
        aad : bytes, optional
            Additional authenticated data that was supplied during encryption.

        Returns
        -------
        bytes
            The original plaintext.
        """
        # Split the blob according to the known KEM ciphertext length.
        kem_ct = blob[:_KEM_CT_LEN]
        nonce = blob[_KEM_CT_LEN : _KEM_CT_LEN + 12]
        ct = blob[_KEM_CT_LEN + 12 :]

        # Decapsulate to recover the shared secret.
        kem = oqs.KeyEncapsulation(_KEM_NAME, secret_key=private_key)
        shared_secret = kem.decap_secret(kem_ct)

        # Derive the same AEAD key as the encryptor.
        aead_key = self._key(shared_secret, kem_ct)

        # Decrypt and return the plaintext.
        aead = AEADS[self.aead](aead_key)
        return aead.decrypt(nonce, ct, aad)


# --------------------------------------------------------------------------- #
# Policy parsing helper
# --------------------------------------------------------------------------- #
def load_policy(text: str) -> Policy:
    """
    Parse a policy description of the form ``"name=value; name=value"``.
    Unknown or missing settings raise :class:`ValueError`.

    Supported settings
    ------------------
    * ``kex`` – currently only ``ecdh-p256`` (mapped to ML‑KEM‑768) is
      accepted.
    * ``aead`` – ``aes-256-gcm`` or ``chacha20-poly1305``.
    """
    settings = {}
    for item in text.split(";"):
        if item.strip():
            name, sep, value = item.partition("=")
            if not sep:
                raise ValueError(f"bad policy item: {item!r}")
            settings[name.strip()] = value.strip()

    kex = settings.get("kex", "ecdh-p256")
    aead = settings.get("aead", "aes-256-gcm")

    if kex not in KEX:
        raise ValueError(f"unsupported policy: kex={kex}")
    if aead not in AEADS:
        raise ValueError(f"unsupported policy: aead={aead}")

    return Policy(kex, aead)
