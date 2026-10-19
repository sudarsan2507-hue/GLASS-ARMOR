"""Document signing service (ML‑DSA‑65, post‑quantum).

A signature covers a purpose label (e.g. "contract", "invoice") together with the
document, so a signature made for one purpose is not valid for another.
Detached signatures for files are stored next to the file as <path>.sig.

The implementation has been migrated from RSA‑PSS to the post‑quantum
ML‑DSA‑65 algorithm provided by liboqs, while preserving the original public
API.
"""
from __future__ import annotations

import oqs
from cryptography.exceptions import InvalidSignature  # kept for backward compatibility


def _signed_bytes(document: bytes, purpose: str) -> bytes:
    """Create the canonical byte representation that is signed.

    The format is identical to the original RSA‑PSS implementation so that any
    existing test vectors that depend on the exact byte layout continue to work.
    """
    return b"pq-gate docsign v1|" + purpose.encode() + b"|" + document


# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(public_key, private_key)`` as raw bytes for a signer.

    The keys are the raw byte strings produced by liboqs; they are not PEM
    encoded.  This matches the original contract of returning ``bytes`` while
    switching to a post‑quantum algorithm.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Signing / verification (in‑memory)
# --------------------------------------------------------------------------- #
def sign_document(private_key: bytes, document: bytes, purpose: str = "general") -> bytes:
    """Sign *document* for the given *purpose* using the supplied private key.

    Returns the raw signature bytes.
    """
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    return signer.sign(_signed_bytes(document, purpose))


def verify_document(
    public_key: bytes,
    document: bytes,
    signature: bytes,
    purpose: str = "general",
) -> bool:
    """Return ``True`` if *signature* is valid for *document* and *purpose*.

    The function mirrors the original RSA‑PSS behaviour: it returns ``False`` on
    any verification failure rather than propagating an exception.
    """
    verifier = oqs.Signature("ML-DSA-65")
    try:
        return verifier.verify(_signed_bytes(document, purpose), signature, public_key)
    except (InvalidSignature, ValueError):
        # ``InvalidSignature`` is kept for compatibility with the previous
        # implementation even though liboqs normally returns a boolean.
        return False


# --------------------------------------------------------------------------- #
# File‑based helpers (detached signatures)
# --------------------------------------------------------------------------- #
def sign_file(path: str, private_key: bytes, purpose: str = "general") -> None:
    """Sign the file at *path* and write the detached signature to ``<path>.sig``."""
    with open(path, "rb") as f:
        document = f.read()
    signature = sign_document(private_key, document, purpose)
    with open(path + ".sig", "wb") as f:
        f.write(signature)


def verify_file(path: str, public_key: bytes, purpose: str = "general") -> bool:
    """Verify the detached signature stored at ``<path>.sig`` against the file.

    Returns ``True`` if the signature is valid, otherwise ``False``.
    """
    try:
        with open(path, "rb") as f:
            document = f.read()
        with open(path + ".sig", "rb") as f:
            signature = f.read()
    except FileNotFoundError:
        return False
    return verify_document(public_key, document, signature, purpose)
