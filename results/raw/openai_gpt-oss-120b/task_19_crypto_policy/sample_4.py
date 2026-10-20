"""Policy‑driven message encryption using post‑quantum primitives.

The original implementation used EC‑DH (P‑256) for key‑exchange.  This version
replaces it with the ML‑KEM‑768 key‑encapsulation mechanism from liboqs while
preserving the public API:

    policy = load_policy("kex=ml-kem-768; aead=aes-256-gcm")
    public_key, private_key = policy.generate_keypair()
    blob = policy.encrypt(public_key, data, aad)      # encrypt
    data = policy.decrypt(private_key, blob, aad)    # decrypt

The encrypted blob layout is:

    KEM ciphertext | nonce (12 bytes) | AEAD ciphertext

The KEM ciphertext length is obtained from the liboqs object
(`oqs.KeyEncapsulation("ML-KEM-768").ciphertext_length`).  The same
`Policy` class can still be instantiated with the legacy `"ecdh-p256"` KEX
if desired – the code retains the original EC implementation for compatibility.
"""

import os
from typing import Tuple

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DEFAULT_POLICY = "kex=ml-kem-768; aead=aes-256-gcm"

# supported AEAD algorithms
AEADS = {
    "aes-256-gcm": AESGCM,
    "chacha20-poly1305": ChaCha20Poly1305,
}

# supported key‑exchange identifiers
KEX = ("ecdh-p256", "ml-kem-768")

# EC‑specific constant (kept for backward compatibility)
_PT = serialization.PublicFormat.UncompressedPoint


# --------------------------------------------------------------------------- #
# Policy implementation
# --------------------------------------------------------------------------- #
class Policy:
    """Encapsulates a single encryption policy.

    Parameters
    ----------
    kex : str
        Key‑exchange algorithm identifier (``"ecdh-p256"`` or ``"ml-kem-768"``).
    aead : str
        AEAD algorithm identifier (must be present in :data:`AEADS`).
    """

    def __init__(self, kex: str, aead: str):
        self.kex = kex
        self.aead = aead

        # Pre‑create the KEM object for length information when needed.
        if self.kex == "ml-kem-768":
            self._kem_proto = oqs.KeyEncapsulation("ML-KEM-768")
        else:
            self._kem_proto = None  # not used for EC‑DH

    # --------------------------------------------------------------------- #
    # Helper: derive the symmetric key from the shared secret.
    # --------------------------------------------------------------------- #
    def _key(self, shared_secret: bytes, context: bytes) -> bytes:
        """
        Derive a 256‑bit key from ``shared_secret`` using HKDF‑SHA256.

        The ``info`` field binds the policy (KEX + AEAD) and the raw KEM/EC
        context (ciphertext or ephemeral public key) to the derived key.
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
    # Key‑pair generation
    # --------------------------------------------------------------------- #
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a (public_key, private_key) pair for the selected KEX.

        Returns
        -------
        tuple[bytes, bytes]
            ``public_key`` – bytes that can be stored or transmitted.
            ``private_key`` – opaque secret bytes; keep them confidential.
        """
        if self.kex == "ml-kem-768":
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            return public_key, private_key

        # ----------------------------------------------------------------- #
        # Legacy EC‑DH path (kept for compatibility)
        # ----------------------------------------------------------------- #
        from cryptography.hazmat.primitives.asymmetric import ec

        private = ec.generate_private_key(ec.SECP256R1())
        public = private.public_key().public_bytes(
            serialization.Encoding.X962, _PT
        )
        private_bytes = private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return public, private_bytes

    # --------------------------------------------------------------------- #
    # Encryption
    # --------------------------------------------------------------------- #
    def encrypt(self, public_key: bytes, data: bytes, aad: bytes = b"") -> bytes:
        """Encrypt ``data`` for the holder of ``public_key``.

        The returned blob can be handed to :meth:`decrypt` together with the
        matching private key.
        """
        if self.kex == "ml-kem-768":
            # ------------------------------------------------------------- #
            # Post‑quantum path – ML‑KEM‑768
            # ------------------------------------------------------------- #
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            ciphertext, shared_secret = kem.encap_secret(public_key)

            # Derive the AEAD key, binding the KEM ciphertext as context.
            key = self._key(shared_secret, ciphertext)

            nonce = os.urandom(12)
            aead = AEADS[self.aead](key)
            encrypted = aead.encrypt(nonce, data, aad)

            # blob = KEM ciphertext | nonce | AEAD ciphertext
            return ciphertext + nonce + encrypted

        # ----------------------------------------------------------------- #
        # Legacy EC‑DH path
        # ----------------------------------------------------------------- #
        from cryptography.hazmat.primitives.asymmetric import ec

        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), public_key
        )
        eph = ec.generate_private_key(ec.SECP256R1())
        eph_pub = eph.public_key().public_bytes(serialization.Encoding.X962, _PT)

        shared_secret = eph.exchange(ec.ECDH(), peer)
        key = self._key(shared_secret, eph_pub)

        nonce = os.urandom(12)
        aead = AEADS[self.aead](key)
        encrypted = aead.encrypt(nonce, data, aad)

        # blob = eph_pub (65 bytes) | nonce (12) | AEAD ciphertext
        return eph_pub + nonce + encrypted

    # --------------------------------------------------------------------- #
    # Decryption
    # --------------------------------------------------------------------- #
    def decrypt(self, private_key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
        """Decrypt a blob produced by :meth:`encrypt`.

        Parameters
        ----------
        private_key : bytes
            The secret key that matches the public key used for encryption.
        blob : bytes
            The encrypted blob (KEM ciphertext + nonce + AEAD ciphertext).
        aad : bytes, optional
            Additional authenticated data passed to the AEAD algorithm.

        Returns
        -------
        bytes
            The original plaintext.
        """
        if self.kex == "ml-kem-768":
            # ------------------------------------------------------------- #
            # Post‑quantum path – ML‑KEM‑768
            # ------------------------------------------------------------- #
            kem_len = self._kem_proto.ciphertext_length
            kem_ct = blob[:kem_len]
            nonce = blob[kem_len : kem_len + 12]
            aead_ct = blob[kem_len + 12 :]

            # Re‑create the KEM object with the secret key.
            kem = oqs.KeyEncapsulation(
                "ML-KEM-768", secret_key=private_key
            )
            shared_secret = kem.decap_secret(kem_ct)

            key = self._key(shared_secret, kem_ct)
            aead = AEADS[self.aead](key)
            return aead.decrypt(nonce, aead_ct, aad)

        # ----------------------------------------------------------------- #
        # Legacy EC‑DH path
        # ----------------------------------------------------------------- #
        from cryptography.hazmat.primitives.asymmetric import ec

        # EC‑DH blob layout: 65‑byte eph_pub | 12‑byte nonce | ciphertext
        eph_pub = blob[:65]
        nonce = blob[65:77]
        aead_ct = blob[77:]

        private = serialization.load_der_private_key(
            private_key, password=None
        )
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), eph_pub
        )
        shared_secret = private.exchange(ec.ECDH(), peer)

        key = self._key(shared_secret, eph_pub)
        aead = AEADS[self.aead](key)
        return aead.decrypt(nonce, aead_ct, aad)


# --------------------------------------------------------------------------- #
# Policy parsing helper
# --------------------------------------------------------------------------- #
def load_policy(text: str) -> Policy:
    """Parse a policy string of the form ``"name=value; name=value"``.

    Supported settings:
        * ``kex`` – key‑exchange algorithm (``ecdh-p256`` or ``ml-kem-768``)
        * ``aead`` – AEAD algorithm (must be present in :data:`AEADS`)

    Raises
    ------
    ValueError
        If an unknown or missing setting is encountered.
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
        raise ValueError(f"unsupported kex: {kex}")
    if aead not in AEADS:
        raise ValueError(f"unsupported aead: {aead}")

    return Policy(kex, aead)
