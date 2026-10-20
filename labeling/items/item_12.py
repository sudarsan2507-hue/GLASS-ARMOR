"""Policy‑driven message encryption using post‑quantum primitives.

The original implementation used an EC Diffie‑Hellman key‑exchange (ECDH‑P256)
and classic AEADs.  This version replaces the key‑exchange with the
post‑quantum KEM **ML‑KEM‑768** from liboqs while keeping the public API
unchanged:

    policy = load_policy("kex=ml-kem-768; aead=aes-256-gcm")
    public_key, private_key = policy.generate_keypair()
    blob = policy.encrypt(public_key, data, aad)          # encrypt
    data = policy.decrypt(private_key, blob, aad)        # decrypt

The encrypted blob layout is:

    | KEM ciphertext (1088 bytes) | nonce (12 bytes) | AEAD ciphertext … |

The KEM ciphertext plays the same role as the former EC “ephemeral public
key”.  The shared secret derived from the KEM is fed to HKDF‑SHA256 together
with the KEM ciphertext (policy‑bound) to obtain the 256‑bit AEAD key.
"""

# --------------------------------------------------------------------------- #
#   Imports
# --------------------------------------------------------------------------- #
import os
from typing import Tuple

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
#   Constants & helper tables
# --------------------------------------------------------------------------- #
DEFAULT_POLICY = "kex=ml-kem-768; aead=aes-256-gcm"

# Mapping from policy name → liboqs algorithm name and fixed ciphertext length.
# Lengths are taken from the ML‑KEM‑768 specification (public key 1184 bytes,
# ciphertext 1088 bytes, shared secret 32 bytes).
_KEM_INFO = {
    "ml-kem-768": {"alg": "ML-KEM-768", "ct_len": 1088},
}

AEADS = {
    "aes-256-gcm": AESGCM,
    "chacha20-poly1305": ChaCha20Poly1305,
}

# The only supported KEX for now – can be extended with other PQ‑KEMs.
KEX = tuple(_KEM_INFO.keys())

# --------------------------------------------------------------------------- #
#   Policy class
# --------------------------------------------------------------------------- #
class Policy:
    """
    Holds the chosen key‑exchange (KEM) and AEAD algorithm.
    """

    def __init__(self, kex: str, aead: str):
        self.kex = kex
        self.aead = aead
        self._kem_alg = _KEM_INFO[kex]["alg"]
        self._kem_ct_len = _KEM_INFO[kex]["ct_len"]

    # ------------------------------------------------------------------- #
    #   Internal helpers
    # ------------------------------------------------------------------- #
    def _derive_key(self, shared_secret: bytes, context: bytes) -> bytes:
        """
        Derive a 256‑bit AEAD key from the KEM shared secret.

        The HKDF info string mirrors the original implementation and is
        bound to the policy, the KEM name and the raw KEM ciphertext (used as
        ``context`` here).
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
    #   Public API
    # ------------------------------------------------------------------- #
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a fresh ML‑KEM key‑pair.

        Returns
        -------
        (public_key, private_key) : Tuple[bytes, bytes]
            * ``public_key`` – the raw KEM public key (bytes)
            * ``private_key`` – the raw KEM secret key (bytes)
        """
        kem = oqs.KeyEncapsulation(self._kem_alg)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return public_key, secret_key

    def encrypt(self, public_key: bytes, data: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt ``data`` for the holder of ``public_key``.

        The function performs:
        1. KEM encapsulation → (kem_ct, shared_secret)
        2. HKDF‑SHA256 over ``shared_secret`` and ``kem_ct`` → AEAD key
        3. Random 12‑byte nonce
        4. AEAD encryption (AES‑GCM or ChaCha20‑Poly1305)

        The returned blob is ``kem_ct || nonce || aead_ciphertext``.
        """
        # 1. KEM encapsulation
        kem = oqs.KeyEncapsulation(self._kem_alg)
        kem_ct, shared_secret = kem.encap_secret(public_key)

        # 2. Derive AEAD key
        aead_key = self._derive_key(shared_secret, kem_ct)

        # 3. Random nonce (12 bytes – suitable for both AEADs)
        nonce = os.urandom(12)

        # 4. AEAD encryption
        aead = AEADS[self.aead](aead_key)
        ct = aead.encrypt(nonce, data, aad)

        # Assemble final blob
        return kem_ct + nonce + ct

    def decrypt(self, private_key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt`.

        Parameters
        ----------
        private_key : bytes
            The KEM secret key belonging to the recipient.
        blob : bytes
            ``kem_ct || nonce || aead_ciphertext`` as produced by ``encrypt``.
        aad : bytes, optional
            Additional authenticated data (must be identical to the value used
            during encryption).

        Returns
        -------
        bytes
            The original plaintext.
        """
        # Split the blob according to the known KEM ciphertext length.
        kem_ct = blob[: self._kem_ct_len]
        nonce = blob[self._kem_ct_len : self._kem_ct_len + 12]
        aead_ct = blob[self._kem_ct_len + 12 :]

        # 1. KEM decapsulation → shared secret
        kem = oqs.KeyEncapsulation(self._kem_alg, secret_key=private_key)
        shared_secret = kem.decap_secret(kem_ct)

        # 2. Derive AEAD key (same context as during encryption)
        aead_key = self._derive_key(shared_secret, kem_ct)

        # 3. AEAD decryption
        aead = AEADS[self.aead](aead_key)
        return aead.decrypt(nonce, aead_ct, aad)


# --------------------------------------------------------------------------- #
#   Policy parsing helper
# --------------------------------------------------------------------------- #
def load_policy(text: str) -> Policy:
    """
    Parse a policy string of the form ``"name=value; name=value"``.

    Supported settings:
        * ``kex`` – key‑exchange algorithm (currently only ``ml-kem-768``)
        * ``aead`` – AEAD algorithm (``aes-256-gcm`` or ``chacha20-poly1305``)

    Raises
    ------
    ValueError
        If the string is malformed or contains unknown/unsupported values.
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
        raise ValueError(f"unsupported KEX algorithm: {kex!r}")
    if aead not in AEADS:
        raise ValueError(f"unsupported AEAD algorithm: {aead!r}")

    return Policy(kex, aead)
