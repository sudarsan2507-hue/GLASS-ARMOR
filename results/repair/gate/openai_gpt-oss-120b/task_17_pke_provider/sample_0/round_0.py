"""Pluggable public-key encryption; the algorithm is chosen from configuration.

    provider = get_provider({"pke": "ml-kem-768"})
    public_key, private_key = provider.generate_keypair()
    blob = provider.encrypt(public_key, data)
    data = provider.decrypt(private_key, blob)

Each message gets a fresh AES‑256‑GCM key, wrapped with the provider's
post‑quantum key‑encapsulation mechanism (ML‑KEM‑768). Unknown algorithm
names are rejected.
"""

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import oqs  # liboqs‑python

# Default configuration now points to the post‑quantum algorithm.
DEFAULT_CONFIG = {"pke": "ml-kem-768"}

# --------------------------------------------------------------------------- #
# ML‑KEM‑768 provider
# --------------------------------------------------------------------------- #
class MlKemProvider:
    """Post‑quantum public‑key encryption using ML‑KEM‑768.

    The public and private keys are raw byte strings returned by liboqs.
    The encrypted blob layout is:

        2‑byte big‑endian length of the KEM ciphertext
        KEM ciphertext (encapsulated key)
        12‑byte AES‑GCM nonce
        AES‑GCM ciphertext (the encrypted payload)
    """

    name = "ml-kem-768"
    _KEM_NAME = "ML-KEM-768"

    def generate_keypair(self):
        """Generate a fresh ML‑KEM‑768 key pair.

        Returns
        -------
        tuple[bytes, bytes]
            (public_key, private_key) where both are raw byte strings.
        """
        kem = oqs.KeyEncapsulation(self._KEM_NAME)
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return public_key, private_key

    def encrypt(self, public_key: bytes, data: bytes) -> bytes:
        """Encrypt ``data`` for the holder of ``public_key``.

        Parameters
        ----------
        public_key : bytes
            The recipient's public key (as returned by ``generate_keypair``).
        data : bytes
            Plaintext to encrypt.

        Returns
        -------
        bytes
            The encrypted blob (see class docstring for layout).
        """
        # 1. Encapsulate a fresh symmetric key using the recipient's public key.
        kem = oqs.KeyEncapsulation(self._KEM_NAME)
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)  # 32‑byte secret

        # 2. Use the shared secret as the AES‑256‑GCM key.
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(12)  # AES‑GCM standard nonce size
        encrypted = aesgcm.encrypt(nonce, data, None)

        # 3. Assemble the final blob.
        return (
            struct.pack(">H", len(kem_ciphertext))
            + kem_ciphertext
            + nonce
            + encrypted
        )

    def decrypt(self, private_key: bytes, blob: bytes) -> bytes:
        """Decrypt ``blob`` using ``private_key``.

        Parameters
        ----------
        private_key : bytes
            The recipient's private key (as returned by ``generate_keypair``).
        blob : bytes
            The encrypted blob produced by :meth:`encrypt`.

        Returns
        -------
        bytes
            The original plaintext.
        """
        # Extract the KEM ciphertext length.
        (kem_len,) = struct.unpack(">H", blob[:2])
        offset = 2

        # Slice out the components.
        kem_ciphertext = blob[offset : offset + kem_len]
        offset += kem_len
        nonce = blob[offset : offset + 12]
        offset += 12
        aes_ciphertext = blob[offset:]

        # Decapsulate to recover the symmetric key.
        kem = oqs.KeyEncapsulation(self._KEM_NAME, secret_key=private_key)
        shared_secret = kem.decap_secret(kem_ciphertext)

        # Decrypt the payload.
        aesgcm = AESGCM(shared_secret)
        return aesgcm.decrypt(nonce, aes_ciphertext, None)


# --------------------------------------------------------------------------- #
# Provider registry and helper functions
# --------------------------------------------------------------------------- #
PROVIDERS = {MlKemProvider.name: MlKemProvider}


def available_algorithms():
    """Return a sorted list of supported algorithm identifiers."""
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for ``config["pke"]`` (default from ``DEFAULT_CONFIG``).

    Parameters
    ----------
    config : dict
        Configuration dictionary that may contain the key ``"pke"``.

    Returns
    -------
    object
        An instance of the requested provider.

    Raises
    ------
    ValueError
        If the requested algorithm is not supported.
    """
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
