"""Pluggable public‑key encryption; the algorithm is chosen from configuration.

    provider = get_provider({"pke": "ml-kem-768"})
    public_key, private_key = provider.generate_keypair()
    blob = provider.encrypt(public_key, data)
    data = provider.decrypt(private_key, blob)

Each message gets a fresh AES‑256‑GCM key, wrapped with the provider's algorithm.
Unknown algorithm names are rejected.
"""

from __future__ import annotations

import os
import struct
from typing import Any, Dict, Tuple

# --------------------------------------------------------------------------- #
#   Post‑quantum cryptography (liboqs)                                        #
# --------------------------------------------------------------------------- #
try:
    import oqs  # type: ignore
except Exception as exc:  # pragma: no cover – liboqs not installed
    raise ImportError(
        "liboqs (python package `oqs`) is required for post‑quantum support"
    ) from exc

# --------------------------------------------------------------------------- #
#   Classical cryptography (kept for backward compatibility)                #
# --------------------------------------------------------------------------- #
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
#   Configuration                                                             #
# --------------------------------------------------------------------------- #
DEFAULT_CONFIG: Dict[str, str] = {"pke": "ml-kem-768"}  # default now uses a post‑quantum scheme

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


# --------------------------------------------------------------------------- #
#   RSA‑OAEP provider (kept for compatibility)                               #
# --------------------------------------------------------------------------- #
class RsaOaepProvider:
    """Classic RSA‑OAEP (2048‑bit) provider – retained for compatibility."""

    name = "rsa-oaep-2048"

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return public, private

    def encrypt(self, public_key: bytes, data: bytes) -> bytes:
        # 1. generate a fresh symmetric key for AES‑256‑GCM
        data_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)

        # 2. wrap the symmetric key with RSA‑OAEP
        wrapped = serialization.load_pem_public_key(public_key).encrypt(data_key, _OAEP)

        # 3. encrypt the payload with AES‑GCM
        ciphertext = AESGCM(data_key).encrypt(nonce, data, None)

        # 4. pack length, wrapped key, nonce and ciphertext
        return struct.pack(">H", len(wrapped)) + wrapped + nonce + ciphertext

    def decrypt(self, private_key: bytes, blob: bytes) -> bytes:
        # unpack length of the wrapped key
        (wrapped_len,) = struct.unpack(">H", blob[:2])
        wrapped = blob[2 : 2 + wrapped_len]
        nonce = blob[2 + wrapped_len : 14 + wrapped_len]
        ciphertext = blob[14 + wrapped_len :]

        # unwrap the symmetric key
        data_key = serialization.load_pem_private_key(private_key, password=None).decrypt(
            wrapped, _OAEP
        )

        # decrypt the payload
        return AESGCM(data_key).decrypt(nonce, ciphertext, None)


# --------------------------------------------------------------------------- #
#   ML‑KEM‑768 provider (post‑quantum)                                        #
# --------------------------------------------------------------------------- #
class MlKemProvider:
    """Post‑quantum KEM provider based on liboqs ML‑KEM‑768."""

    name = "ml-kem-768"
    _KEM_NAME = "ML-KEM-768"

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a public/secret key pair.

        Returns
        -------
        tuple[bytes, bytes]
            (public_key, secret_key) – both are raw byte strings as emitted by liboqs.
        """
        kem = oqs.KeyEncapsulation(self._KEM_NAME)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return public_key, secret_key

    def encrypt(self, public_key: bytes, data: bytes) -> bytes:
        """
        Encrypt ``data`` for the holder of ``public_key``.

        The routine:
        1. Performs a KEM encapsulation to obtain a fresh 256‑bit shared secret.
        2. Uses that secret as the AES‑256‑GCM key.
        3. Returns a blob containing:
           - 2‑byte big‑endian length of the encapsulated ciphertext,
           - the encapsulated ciphertext itself,
           - a 12‑byte nonce,
           - the AES‑GCM ciphertext.

        Parameters
        ----------
        public_key : bytes
            Public key generated by :meth:`generate_keypair`.
        data : bytes
            Plaintext to encrypt.

        Returns
        -------
        bytes
            The encrypted blob.
        """
        # 1. KEM encapsulation – yields (encapsulated_ct, shared_secret)
        encapsulated_ct, shared_secret = oqs.KeyEncapsulation(self._KEM_NAME).encap_secret(
            public_key
        )

        # 2. AES‑256‑GCM with the shared secret as key
        nonce = os.urandom(12)
        aesgcm = AESGCM(shared_secret)  # 32 bytes = 256 bits for ML‑KEM‑768
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # 3. Assemble the final blob
        return (
            struct.pack(">H", len(encapsulated_ct))
            + encapsulated_ct
            + nonce
            + ciphertext
        )

    def decrypt(self, secret_key: bytes, blob: bytes) -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt`.

        Parameters
        ----------
        secret_key : bytes
            Secret key generated by :meth:`generate_keypair`.
        blob : bytes
            The encrypted blob.

        Returns
        -------
        bytes
            The original plaintext.
        """
        # Extract components
        (enc_len,) = struct.unpack(">H", blob[:2])
        encapsulated_ct = blob[2 : 2 + enc_len]
        nonce = blob[2 + enc_len : 14 + enc_len]
        ciphertext = blob[14 + enc_len :]

        # Decapsulate to recover the shared secret (AES key)
        kem = oqs.KeyEncapsulation(self._KEM_NAME, secret_key=secret_key)
        shared_secret = kem.decap_secret(encapsulated_ct)

        # Decrypt with AES‑256‑GCM
        aesgcm = AESGCM(shared_secret)
        return aesgcm.decrypt(nonce, ciphertext, None)


# --------------------------------------------------------------------------- #
#   Provider registry                                                          #
# --------------------------------------------------------------------------- #
PROVIDERS: Dict[str, Any] = {
    RsaOaepProvider.name: RsaOaepProvider,
    MlKemProvider.name: MlKemProvider,
}


def available_algorithms() -> list[str]:
    """Return a sorted list of supported algorithm identifiers."""
    return sorted(PROVIDERS)


def get_provider(config: Dict[str, Any] | None = None) -> Any:
    """Return a provider instance for ``config["pke"]`` (default from ``DEFAULT_CONFIG``).

    Parameters
    ----------
    config : dict or None
        Configuration dictionary.  The key ``"pke"`` selects the algorithm.
        If ``None`` or empty, the default configuration is used.

    Returns
    -------
    object
        An instance of the selected provider class.

    Raises
    ------
    ValueError
        If the requested algorithm is not known.
    """
    cfg = config or {}
    name = cfg.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()


__all__ = [
    "RsaOaepProvider",
    "MlKemProvider",
    "available_algorithms",
    "get_provider",
    "DEFAULT_CONFIG",
]
