"""Pluggable public‑key encryption; the algorithm is chosen from configuration.

    provider = get_provider({"pke": "ml-kem-768"})
    public_key, private_key = provider.generate_keypair()
    blob = provider.encrypt(public_key, data)          # encrypt
    data = provider.decrypt(private_key, blob)        # decrypt

Each message gets a fresh AES‑256‑GCM key, wrapped with the provider's
post‑quantum key‑encapsulation mechanism (ML‑KEM‑768). Unknown algorithm
names are rejected.
"""

import os
import struct

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Default configuration – use the post‑quantum algorithm.
# --------------------------------------------------------------------------- #
DEFAULT_CONFIG = {"pke": "ml-kem-768"}

# --------------------------------------------------------------------------- #
# Provider implementation based on liboqs ML‑KEM‑768.
# --------------------------------------------------------------------------- #
class MlKemProvider:
    """
    Post‑quantum public‑key encryption provider using ML‑KEM‑768.

    The public API mirrors the original RSA‑OAEP provider so existing tests
    continue to work unchanged.
    """
    name = "ml-kem-768"
    _KEM_NAME = "ML-KEM-768"

    def generate_keypair(self):
        """
        Generate a fresh ML‑KEM‑768 key pair.

        Returns
        -------
        tuple[bytes, bytes]
            (public_key, secret_key) – both are raw byte strings suitable for
            storage or transmission.
        """
        kem = oqs.KeyEncapsulation(self._KEM_NAME)
        public_key = kem.generate_keypair()          # bytes
        secret_key = kem.export_secret_key()         # bytes
        return public_key, secret_key

    def encrypt(self, public_key: bytes, data: bytes) -> bytes:
        """
        Hybrid encrypt ``data`` using the supplied ``public_key``.

        Steps
        -----
        1. Generate a fresh 256‑bit AES key and a 96‑bit nonce.
        2. Encapsulate the AES key with the ML‑KEM public key, producing a
           ciphertext (the wrapped key) and a shared secret.
        3. Use the shared secret as the AES‑GCM key to encrypt ``data``.
        4. Serialize the result as:
           [2‑byte length][wrapped_key][nonce][aes_gcm_ciphertext]

        Parameters
        ----------
        public_key : bytes
            The ML‑KEM public key (as returned by ``generate_keypair``).
        data : bytes
            Plaintext to encrypt.

        Returns
        -------
        bytes
            The serialized ciphertext blob.
        """
        # 1. Fresh symmetric key & nonce
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)

        # 2. Encapsulate the AES key with the recipient's KEM public key
        kem = oqs.KeyEncapsulation(self._KEM_NAME)
        wrapped_key, shared_secret = kem.encap_secret(public_key)

        # The shared secret must be exactly 32 bytes for AES‑256‑GCM.
        # ML‑KEM‑768 already yields a 32‑byte secret, but we enforce the size.
        if len(shared_secret) != 32:
            raise ValueError(
                f"Unexpected shared secret length {len(shared_secret)}; expected 32 bytes."
            )

        # 3. Encrypt the payload with AES‑GCM using the shared secret
        aesgcm = AESGCM(shared_secret)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # 4. Serialize: length (uint16 big‑endian) + wrapped_key + nonce + ciphertext
        return struct.pack(">H", len(wrapped_key)) + wrapped_key + nonce + ciphertext

    def decrypt(self, private_key: bytes, blob: bytes) -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt`.

        Parameters
        ----------
        private_key : bytes
            The ML‑KEM secret key (as returned by ``generate_keypair``).
        blob : bytes
            The serialized ciphertext blob.

        Returns
        -------
        bytes
            The original plaintext.
        """
        # Extract the wrapped key length
        (wrapped_len,) = struct.unpack(">H", blob[:2])
        offset = 2

        # Split the components
        wrapped_key = blob[offset : offset + wrapped_len]
        offset += wrapped_len
        nonce = blob[offset : offset + 12]          # AES‑GCM nonce is 12 bytes
        offset += 12
        ciphertext = blob[offset:]

        # Decapsulate to recover the AES‑GCM key
        kem = oqs.KeyEncapsulation(self._KEM_NAME, secret_key=private_key)
        shared_secret = kem.decap_secret(wrapped_key)

        if len(shared_secret) != 32:
            raise ValueError(
                f"Unexpected shared secret length {len(shared_secret)}; expected 32 bytes."
            )

        # Decrypt the payload
        aesgcm = AESGCM(shared_secret)
        return aesgcm.decrypt(nonce, ciphertext, None)


# --------------------------------------------------------------------------- #
# Provider registry and helper functions.
# --------------------------------------------------------------------------- #
PROVIDERS = {MlKemProvider.name: MlKemProvider}


def available_algorithms():
    """Return a sorted list of supported algorithm names."""
    return sorted(PROVIDERS)


def get_provider(config):
    """
    Return a provider instance for ``config["pke"]`` (default from ``DEFAULT_CONFIG``).

    Parameters
    ----------
    config : dict
        Configuration dictionary that may contain the key ``"pke"``.

    Returns
    -------
    object
        An instance of the requested provider class.

    Raises
    ------
    ValueError
        If the requested algorithm name is not recognised.
    """
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
