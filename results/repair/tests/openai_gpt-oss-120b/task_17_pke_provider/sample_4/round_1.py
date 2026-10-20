"""Pluggable public‑key encryption; the algorithm is chosen from configuration.

    provider = get_provider({"pke": "ml-kem-768"})
    public_key, private_key = provider.generate_keypair()
    blob = provider.encrypt(public_key, data)          # data = bytes
    data = provider.decrypt(private_key, blob)

Each message gets a fresh AES‑256‑GCM key, wrapped with the provider's
post‑quantum key‑encapsulation mechanism (ML‑KEM‑768).  Unknown algorithm
names are rejected.
"""

from __future__ import annotations

import os
import struct
from typing import Tuple, List

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Post‑quantum Key‑Encapsulation Provider (ML‑KEM‑768)
# --------------------------------------------------------------------------- #
class MlKemProvider:
    """
    Provider that uses the ML‑KEM‑768 algorithm from liboqs for public‑key
    encryption.  The public API mirrors the original RSA‑OAEP provider so
    existing tests continue to work.
    """
    name = "ml-kem-768"

    def __init__(self) -> None:
        # The algorithm name is fixed; liboqs validates it at runtime.
        self._alg = "ML-KEM-768"

    # --------------------------------------------------------------------- #
    # Key generation
    # --------------------------------------------------------------------- #
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a fresh ML‑KEM‑768 key pair.

        Returns
        -------
        (public_key_bytes, private_key_bytes)
            * ``public_key_bytes`` – the public key that can be shared.
            * ``private_key_bytes`` – the secret key that must be kept
              confidential.  It is the raw secret‑key export from liboqs.
        """
        kem = oqs.KeyEncapsulation(self._alg)
        public_key = kem.generate_keypair()          # bytes
        secret_key = kem.export_secret_key()         # bytes
        # Explicitly delete the temporary object to free native resources.
        del kem
        return public_key, secret_key

    # --------------------------------------------------------------------- #
    # Encryption (encapsulation + symmetric encryption)
    # --------------------------------------------------------------------- #
    def encrypt(self, public_key: bytes, data: bytes) -> bytes:
        """
        Encrypt ``data`` for the holder of ``public_key``.

        The procedure is:
        1. Generate a fresh AES‑256‑GCM nonce.
        2. Encapsulate a symmetric key with the recipient's ML‑KEM public key,
           yielding ``kem_ciphertext`` and the shared secret (the AES key).
        3. Encrypt ``data`` with AES‑256‑GCM using the shared secret.
        4. Serialize the result as:
           ``<2‑byte length><kem_ciphertext><nonce><aes_ciphertext>``

        Parameters
        ----------
        public_key : bytes
            Public key produced by :meth:`generate_keypair`.
        data : bytes
            Plaintext to encrypt.

        Returns
        -------
        bytes
            The encrypted blob that can be passed to :meth:`decrypt`.
        """
        # 1. Fresh nonce for AES‑GCM
        nonce = os.urandom(12)

        # 2. KEM encapsulation
        kem = oqs.KeyEncapsulation(self._alg)
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)

        # The shared secret must be exactly 32 bytes for AES‑256‑GCM.
        if len(shared_secret) != 32:
            raise ValueError(
                f"Unexpected shared secret length {len(shared_secret)}; "
                "expected 32 bytes for AES‑256‑GCM."
            )

        # 3. Symmetric encryption (the shared secret is the AES‑GCM key)
        aesgcm = AESGCM(shared_secret)
        aes_ciphertext = aesgcm.encrypt(nonce, data, None)

        # 4. Serialize
        if len(kem_ciphertext) > 0xFFFF:
            raise ValueError("KEM ciphertext too large to encode length in 2 bytes")
        blob = struct.pack(">H", len(kem_ciphertext)) + kem_ciphertext + nonce + aes_ciphertext

        # Clean up native objects
        del kem, aesgcm

        return blob

    # --------------------------------------------------------------------- #
    # Decryption (decapsulation + symmetric decryption)
    # --------------------------------------------------------------------- #
    def decrypt(self, private_key: bytes, blob: bytes) -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt`.

        Parameters
        ----------
        private_key : bytes
            Secret key produced by :meth:`generate_keypair`.
        blob : bytes
            The encrypted blob.

        Returns
        -------
        bytes
            The original plaintext.
        """
        # Minimum size: 2‑byte length + at least 0‑byte KEM ciphertext + 12‑byte nonce
        if len(blob) < 14:
            raise ValueError("Blob is too short to contain required fields")

        # Extract the KEM ciphertext length
        try:
            (kem_len,) = struct.unpack(">H", blob[:2])
        except struct.error as exc:
            raise ValueError("Failed to unpack KEM length") from exc

        expected_min_len = 2 + kem_len + 12  # length field + KEM ct + nonce
        if len(blob) < expected_min_len:
            raise ValueError("Blob is truncated or malformed")

        kem_ciphertext = blob[2 : 2 + kem_len]
        nonce = blob[2 + kem_len : 14 + kem_len]          # 12‑byte nonce
        aes_ciphertext = blob[14 + kem_len :]

        # Decapsulate to recover the AES key
        kem = oqs.KeyEncapsulation(self._alg, secret_key=private_key)
        shared_secret = kem.decap_secret(kem_ciphertext)

        if len(shared_secret) != 32:
            raise ValueError(
                f"Unexpected shared secret length {len(shared_secret)}; "
                "expected 32 bytes for AES‑256‑GCM."
            )

        # Symmetric decryption
        aesgcm = AESGCM(shared_secret)
        plaintext = aesgcm.decrypt(nonce, aes_ciphertext, None)

        # Clean up native objects
        del kem, aesgcm

        return plaintext


# --------------------------------------------------------------------------- #
# Optional Post‑quantum Signature Provider (ML‑DSA‑65)
# --------------------------------------------------------------------------- #
class MlDsaProvider:
    """
    Provider that uses the ML‑DSA‑65 algorithm from liboqs for digital
    signatures.  It is not used by the encryption API but is supplied for
    completeness and future extensibility.
    """
    name = "ml-dsa-65"

    def __init__(self) -> None:
        self._alg = "ML-DSA-65"

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a fresh ML‑DSA‑65 key pair.

        Returns
        -------
        (public_key_bytes, private_key_bytes)
        """
        sig = oqs.Signature(self._alg)
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        del sig
        return public_key, secret_key

    def sign(self, private_key: bytes, message: bytes, context: bytes | None = None) -> bytes:
        """
        Sign ``message`` (optionally with a domain‑separation ``context``).

        Parameters
        ----------
        private_key : bytes
            Secret key from :meth:`generate_keypair`.
        message : bytes
            Message to sign.
        context : bytes or None
            Optional context string; if provided, the context‑aware API is used.

        Returns
        -------
        bytes
            The signature.
        """
        sig = oqs.Signature(self._alg, secret_key=private_key)
        if context is None:
            signature = sig.sign(message)
        else:
            # liboqs expects a *string* for the context‑aware API; decode if bytes.
            ctx_str = context.decode() if isinstance(context, (bytes, bytearray)) else str(context)
            signature = sig.sign_with_ctx_str(message, ctx_str)
        del sig
        return signature

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes | None = None,
    ) -> bool:
        """
        Verify a signature.

        Parameters
        ----------
        public_key : bytes
            Public key from :meth:`generate_keypair`.
        message : bytes
            Original message.
        signature : bytes
            Signature to verify.
        context : bytes or None
            Optional context string; if provided, the context‑aware API is used.

        Returns
        -------
        bool
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        verifier = oqs.Signature(self._alg)
        if context is None:
            ok = verifier.verify(message, signature, public_key)
        else:
            ctx_str = context.decode() if isinstance(context, (bytes, bytearray)) else str(context)
            ok = verifier.verify_with_ctx_str(message, signature, ctx_str, public_key)
        del verifier
        return ok


# --------------------------------------------------------------------------- #
# Provider registry and helper functions
# --------------------------------------------------------------------------- #
DEFAULT_CONFIG = {"pke": "ml-kem-768"}

PROVIDERS = {
    MlKemProvider.name: MlKemProvider,
    MlDsaProvider.name: MlDsaProvider,   # exposed for completeness
}


def available_algorithms() -> List[str]:
    """Return a sorted list of supported algorithm identifiers."""
    return sorted(PROVIDERS)


def get_provider(config: dict) -> MlKemProvider | MlDsaProvider:
    """
    Return a provider instance for ``config["pke"]`` (default taken from
    ``DEFAULT_CONFIG``).  Raises ``ValueError`` for unknown identifiers.
    """
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()


__all__ = [
    "MlKemProvider",
    "MlDsaProvider",
    "available_algorithms",
    "get_provider",
    "DEFAULT_CONFIG",
    "PROVIDERS",
]
