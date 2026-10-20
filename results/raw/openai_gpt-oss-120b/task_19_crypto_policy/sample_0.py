"""Policy‑driven message encryption using post‑quantum cryptography.

The original implementation used EC‑DH (P‑256) for key‑exchange.  This version
replaces it with the NIST‑approved post‑quantum algorithm **ML‑KEM‑768**
from liboqs.  The public API (``Policy`` class, ``load_policy`` function and
the signatures of ``generate_keypair``, ``encrypt`` and ``decrypt``) is
unchanged, so existing tests continue to work.

Encryption is “KEM‑style”: the sender encapsulates a shared secret with the
recipient’s public key, derives an AEAD key with HKDF‑SHA256 (bound to the
policy and the KEM ciphertext), and finally encrypts the payload with the
chosen AEAD algorithm.

The blob layout is::

    KEM ciphertext | nonce (12 bytes) | AEAD ciphertext

The KEM ciphertext length for ML‑KEM‑768 is 1088 bytes (fixed for this
algorithm).  The secret key returned by ``generate_keypair`` is the raw
bytes exported by liboqs and can be stored directly.

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
#   Constants & supported algorithms
# --------------------------------------------------------------------------- #
# Default policy string kept for backward compatibility.
DEFAULT_POLICY = "kex=ecdh-p256; aead=aes-256-gcm"

# Mapping of AEAD names to their implementations.
AEADS = {
    "aes-256-gcm": AESGCM,
    "chacha20-poly1305": ChaCha20Poly1305,
}

# Supported key‑exchange identifiers.  ``ecdh-p256`` is retained for legacy
# configuration files but is internally mapped to the post‑quantum algorithm.
KEX = ("ecdh-p256", "ml-kem-768")

# liboqs algorithm name for the post‑quantum KEM we use.
_KEM_ALG = "ML-KEM-768"

# Fixed ciphertext length for ML‑KEM‑768 (see liboqs documentation).
_KEM_CT_LEN = 1088  # bytes

# --------------------------------------------------------------------------- #
#   Helper – HKDF key derivation
# --------------------------------------------------------------------------- #
def _hkdf_derive(shared_secret: bytes, context: bytes, kex: str, aead: str) -> bytes:
    """
    Derive a 32‑byte AEAD key from the KEM shared secret.

    The ``info`` field binds the derived key to the policy (kex + aead) and
    to the raw KEM ciphertext (passed as ``context``).  This mirrors the
    original EC‑DH implementation.
    """
    info = f"pq-gate policy v1|{kex}|{aead}|".encode() + context
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
#   Policy class
# --------------------------------------------------------------------------- #
class Policy:
    """
    A policy bundles a key‑exchange algorithm and an AEAD algorithm.
    The public interface matches the original EC‑based version.
    """

    def __init__(self, kex: str, aead: str):
        self.kex = kex
        self.aead = aead

    # ------------------------------------------------------------------- #
    #   Key‑pair generation
    # ------------------------------------------------------------------- #
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a (public_key, private_key) pair for the selected KEX.

        For the post‑quantum path we use liboqs’ ``KeyEncapsulation`` API.
        The returned keys are raw byte strings suitable for later
        ``encrypt``/``decrypt`` calls.
        """
        if self.kex in ("ml-kem-768", "ecdh-p256"):
            # Both identifiers map to the same post‑quantum KEM.
            kem = oqs.KeyEncapsulation(_KEM_ALG)
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            return public_key, private_key
        else:
            raise ValueError(f"Unsupported KEX algorithm: {self.kex}")

    # ------------------------------------------------------------------- #
    #   Encryption
    # ------------------------------------------------------------------- #
    def encrypt(self, public_key: bytes, data: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt ``data`` for the holder of ``public_key``.

        The function:
          1. Performs a KEM encapsulation → (ct, shared_secret).
          2. Derives an AEAD key with HKDF‑SHA256 (policy‑bound).
          3. Encrypts the payload with the chosen AEAD.
          4. Returns ``ct || nonce || ciphertext``.
        """
        if self.kex not in ("ml-kem-768", "ecdh-p256"):
            raise ValueError(f"Unsupported KEX algorithm: {self.kex}")

        # 1️⃣  KEM encapsulation
        kem = oqs.KeyEncapsulation(_KEM_ALG)
        ciphertext, shared_secret = kem.encap_secret(public_key)

        # 2️⃣  Derive AEAD key (policy‑bound)
        aead_key = _hkdf_derive(shared_secret, ciphertext, self.kex, self.aead)

        # 3️⃣  AEAD encryption
        nonce = os.urandom(12)  # 96‑bit nonce, same size as before
        aead = AEADS[self.aead](aead_key)
        encrypted = aead.encrypt(nonce, data, aad)

        # 4️⃣  Assemble final blob
        return ciphertext + nonce + encrypted

    # ------------------------------------------------------------------- #
    #   Decryption
    # ------------------------------------------------------------------- #
    def decrypt(self, private_key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt a blob produced by :meth:`encrypt`.

        The blob layout is ``ct || nonce || ciphertext`` where ``ct`` is the
        KEM ciphertext (fixed length for ML‑KEM‑768).  The function:
          1. Splits the blob.
          2. Decapsulates the shared secret.
          3. Derives the same AEAD key.
          4. Decrypts the payload.
        """
        if self.kex not in ("ml-kem-768", "ecdh-p256"):
            raise ValueError(f"Unsupported KEX algorithm: {self.kex}")

        # 1️⃣  Split the blob
        ct = blob[:_KEM_CT_LEN]
        nonce = blob[_KEM_CT_LEN : _KEM_CT_LEN + 12]
        ciphertext = blob[_KEM_CT_LEN + 12 :]

        # 2️⃣  Decapsulate
        kem = oqs.KeyEncapsulation(_KEM_ALG, secret_key=private_key)
        shared_secret = kem.decap_secret(ct)

        # 3️⃣  Derive AEAD key (must match encryption)
        aead_key = _hkdf_derive(shared_secret, ct, self.kex, self.aead)

        # 4️⃣  AEAD decryption
        aead = AEADS[self.aead](aead_key)
        return aead.decrypt(nonce, ciphertext, aad)


# --------------------------------------------------------------------------- #
#   Policy parsing helper
# --------------------------------------------------------------------------- #
def load_policy(text: str) -> Policy:
    """
    Parse a policy string of the form ``"name=value; name=value"``.
    Raises ``ValueError`` for unknown or missing settings.

    Supported keys:
        * ``kex`` – key‑exchange algorithm (``ecdh-p256`` or ``ml-kem-768``)
        * ``aead`` – AEAD algorithm (``aes-256-gcm`` or ``chacha20-poly1305``)

    The legacy identifier ``ecdh-p256`` is accepted for backward
    compatibility and maps to the post‑quantum ML‑KEM‑768 algorithm.
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

    # Normalise legacy identifier to the actual implementation name.
    if kex == "ecdh-p256":
        kex = "ml-kem-768"

    if kex not in KEX or aead not in AEADS:
        raise ValueError(f"unsupported policy: kex={kex} aead={aead}")

    return Policy(kex, aead)
