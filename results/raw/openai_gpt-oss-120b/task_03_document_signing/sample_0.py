"""Document signing service (ML‑DSA‑65, post‑quantum).

A signature covers a purpose label (e.g. "contract", "invoice") together with the
document, so a signature made for one purpose is not valid for another.
Detached signatures for files are stored next to the file as <path>.sig.

The public API (generate_keypair, sign_document, verify_document,
sign_file, verify_file) is unchanged, but the implementation now uses the
post‑quantum ML‑DSA‑65 algorithm from liboqs.
"""

from __future__ import annotations

import oqs
from cryptography.exceptions import InvalidSignature  # kept for compatibility


def _signed_bytes(document: bytes, purpose: str) -> bytes:
    """Create the canonical byte representation that is signed.

    The format is identical to the original RSA‑PSS version so that any
    external tooling that inspects the signed payload continues to work.
    """
    return b"pq-gate docsign v1|" + purpose.encode() + b"|" + document


# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, private_key) as raw bytes for a signer.

    The keys are generated with the ML‑DSA‑65 algorithm.  The returned values
    are the raw binary representations produced by liboqs; they are opaque
    to callers and can be stored directly (e.g. in PEM‑like files if desired).
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Signing / verification
# --------------------------------------------------------------------------- #
def sign_document(private_key: bytes, document: bytes, purpose: str = "general") -> bytes:
    """Sign *document* for the given *purpose* using the supplied private key.

    Returns the raw signature bytes.
    """
    # Initialise a Signature object with the secret key.
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    # The message that is actually signed includes the purpose label.
    msg = _signed_bytes(document, purpose)
    return signer.sign(msg)


def verify_document(
    public_key: bytes,
    document: bytes,
    signature: bytes,
    purpose: str = "general",
) -> bool:
    """Return ``True`` if *signature* is a valid signature for *document* and *purpose*.

    The function catches any liboqs verification errors and normalises the
    result to a boolean, mirroring the behaviour of the original RSA‑PSS
    implementation.
    """
    verifier = oqs.Signature("ML-DSA-65")
    msg = _signed_bytes(document, purpose)
    try:
        return verifier.verify(msg, signature, public_key)
    except (InvalidSignature, OSError, ValueError):
        # liboqs may raise OSError on verification failure; treat it as False.
        return False


# --------------------------------------------------------------------------- #
# File helpers
# --------------------------------------------------------------------------- #
def sign_file(path: str, private_key: bytes, purpose: str = "general") -> None:
    """Sign the file at *path* and write the signature to ``<path>.sig``."""
    with open(path, "rb") as f:
        document = f.read()
    signature = sign_document(private_key, document, purpose)
    with open(path + ".sig", "wb") as f:
        f.write(signature)


def verify_file(path: str, public_key: bytes, purpose: str = "general") -> bool:
    """Check ``<path>.sig`` against the file at *path*.  Returns ``True`` or ``False``."""
    with open(path, "rb") as f:
        document = f.read()
    try:
        with open(path + ".sig", "rb") as f:
            signature = f.read()
    except FileNotFoundError:
        return False
    return verify_document(public_key, document, signature, purpose)
