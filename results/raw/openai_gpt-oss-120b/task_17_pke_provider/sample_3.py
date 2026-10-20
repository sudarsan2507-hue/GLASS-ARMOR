"""Pluggable public-key encryption; the algorithm is chosen from configuration.

    provider = get_provider({"pke": "ml-kem-768"})
    public_key, private_key = provider.generate_keypair()
    blob = provider.encrypt(public_key, data);  data = provider.decrypt(private_key, blob)

Each message gets a fresh AES-256-GCM key, wrapped with the provider's algorithm.
Unknown algorithm names are rejected.
"""

import os
import struct

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG = {"pke": "ml-kem-768"}

# --------------------------------------------------------------------------- #
# Helper – derive a 256‑bit AES key from a KEM shared secret
# --------------------------------------------------------------------------- #

def _derive_aes_key(shared_secret: bytes) -> bytes:
    """Derive a 32‑byte AES‑256‑GCM key from the KEM shared secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pke-aes-key",
    )
    return hkdf.derive(shared_secret)


# --------------------------------------------------------------------------- #
# ML‑KEM‑768 provider
# --------------------------------------------------------------------------- #

class MlKem768Provider:
    """Post‑quantum public‑key encryption using ML‑KEM‑768."""

    name = "ml-kem-768"

    def __init__(self):
        # The algorithm name as understood by liboqs
        self._alg = "ML-KEM-768"

    # --------------------------------------------------------------------- #
    # Key generation
    # --------------------------------------------------------------------- #
    def generate_keypair(self):
        """
        Generate a fresh ML‑KEM‑768 key pair.

        Returns
        -------
        tuple[bytes, bytes]
            (public_key, private_key) – both in raw byte form suitable for
            storage or transmission.
        """
        kem = oqs.KeyEncapsulation(self._alg)
        public_key = kem.generate_keypair()          # bytes
        secret_key = kem.export_secret_key()         # bytes
        return public_key, secret_key

    # --------------------------------------------------------------------- #
    # Encryption
    # --------------------------------------------------------------------- #
    def encrypt(self, public_key: bytes, data: bytes) -> bytes:
        """
        Encrypt ``data`` for the holder of ``public_key``.

        The function:
        1. Generates a fresh AES‑256‑GCM key.
        2. Uses ML‑KEM‑768 to encapsulate a shared secret; the secret is
           transformed into the AES key via HKDF.
        3. Wraps the AES key (the KEM ciphertext) together with the nonce
           and the AES‑GCM ciphertext.

        The returned blob layout is:

        ``[2‑byte length][KEM ciphertext][12‑byte nonce][AES‑GCM ciphertext]``

        Parameters
        ----------
        public_key : bytes
            Raw public key as produced by :meth:`generate_keypair`.
        data : bytes
            Plaintext to encrypt.

        Returns
        -------
        bytes
            The encrypted blob.
        """
        # 1. Fresh AES‑256‑GCM key (derived from KEM shared secret later)
        #    We still need a random key for the encapsulation step; liboqs
        #    returns a 32‑byte shared secret which we turn into the AES key.
        # 2. Perform KEM encapsulation
        kem = oqs.KeyEncapsulation(self._alg)
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)

        # 3. Derive the AES key from the shared secret
        aes_key = _derive_aes_key(shared_secret)

        # 4. AES‑GCM encrypt the payload
        nonce = os.urandom(12)                     # 96‑bit nonce per AES‑GCM spec
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # 5. Assemble the final blob
        wrapped_len = struct.pack(">H", len(kem_ciphertext))
        return wrapped_len + kem_ciphertext + nonce + ciphertext

    # --------------------------------------------------------------------- #
    # Decryption
    # --------------------------------------------------------------------- #
    def decrypt(self, private_key: bytes, blob: bytes) -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt`.

        Parameters
        ----------
        private_key : bytes
            Raw private key as produced by :meth:`generate_keypair`.
        blob : bytes
            The encrypted blob.

        Returns
        -------
        bytes
            The original plaintext.
        """
        # Extract lengths and components
        (kem_len,) = struct.unpack(">H", blob[:2])
        kem_ciphertext = blob[2 : 2 + kem_len]
        nonce = blob[2 + kem_len : 14 + kem_len]          # 12‑byte nonce
        ciphertext = blob[14 + kem_len :]

        # Decapsulate to obtain the shared secret
        kem = oqs.KeyEncapsulation(self._alg, secret_key=private_key)
        shared_secret = kem.decap_secret(kem_ciphertext)

        # Derive the AES key and decrypt
        aes_key = _derive_aes_key(shared_secret)
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None)


# --------------------------------------------------------------------------- #
# Provider registry
# --------------------------------------------------------------------------- #

PROVIDERS = {MlKem768Provider.name: MlKem768Provider}


def available_algorithms():
    """Return a sorted list of supported algorithm identifiers."""
    return sorted(PROVIDERS)


def get_provider(config):
    """Return a provider instance for ``config["pke"]`` (default from ``DEFAULT_CONFIG``)."""
    name = config.get("pke", DEFAULT_CONFIG["pke"])
    if name not in PROVIDERS:
        raise ValueError(f"unsupported algorithm: {name}")
    return PROVIDERS[name]()
