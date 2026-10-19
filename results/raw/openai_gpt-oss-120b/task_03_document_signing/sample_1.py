"""Document signing service (ML‑DSA‑65, post‑quantum).

A signature covers a purpose label (e.g. "contract", "invoice") together with the
document, so a signature made for one purpose is not valid for another.
Detached signatures for files are stored next to the file as <path>.sig.

The implementation has been migrated from RSA‑PSS to the post‑quantum
ML‑DSA‑65 algorithm using the liboqs Python bindings.  The public API
(`generate_keypair`, `sign_document`, `verify_document`, `sign_file`,
`verify_file`) is unchanged, so existing tests continue to work.
"""
from __future__ import annotations

import oqs
from cryptography.exceptions import InvalidSignature  # kept for compatibility


# --------------------------------------------------------------------------- #
# Helper
# --------------------------------------------------------------------------- #
def _signed_bytes(document: bytes, purpose: str) -> bytes:
    """
    Construct the byte sequence that is actually signed.

    The format is deliberately stable so that signatures are bound to both the
    document content and the intended purpose.
    """
    return b"pq-gate docsign v1|" + purpose.encode() + b"|" + document


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a new ML‑DSA‑65 key pair.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        * ``public_key`` – raw public‑key bytes as produced by liboqs.
        * ``private_key`` – raw secret‑key bytes as produced by liboqs.

    The returned values are compatible with the other functions in this module;
    they are **not** PEM‑encoded.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    # Explicitly free the OQS object (optional, but nice for deterministic cleanup)
    sig.free()
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Signing / verification
# --------------------------------------------------------------------------- #
def sign_document(private_key: bytes, document: bytes, purpose: str = "general") -> bytes:
    """
    Sign a document for a given purpose using the supplied private key.

    Parameters
    ----------
    private_key : bytes
        The secret key returned by :func:`generate_keypair`.
    document : bytes
        The raw document data to be signed.
    purpose : str, optional
        Logical label that is bound into the signature (default ``"general"``).

    Returns
    -------
    signature : bytes
        The ML‑DSA‑65 signature.
    """
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    try:
        signature = signer.sign(_signed_bytes(document, purpose))
    finally:
        signer.free()
    return signature


def verify_document(
    public_key: bytes,
    document: bytes,
    signature: bytes,
    purpose: str = "general",
) -> bool:
    """
    Verify that ``signature`` is a valid ML‑DSA‑65 signature for ``document``
    and ``purpose`` using the supplied public key.

    Returns ``True`` if the signature is valid, otherwise ``False``.
    """
    verifier = oqs.Signature("ML-DSA-65")
    try:
        # liboqs returns a boolean; we catch any unexpected exception and treat it
        # as a verification failure to keep the original API contract.
        return verifier.verify(_signed_bytes(document, purpose), signature, public_key)
    except Exception:  # pragma: no cover – defensive, liboqs should not raise here
        return False
    finally:
        verifier.free()


# --------------------------------------------------------------------------- #
# File helpers
# --------------------------------------------------------------------------- #
def sign_file(path: str, private_key: bytes, purpose: str = "general") -> None:
    """
    Sign the file located at ``path`` and write the detached signature to
    ``<path>.sig``.
    """
    with open(path, "rb") as f:
        document = f.read()
    signature = sign_document(private_key, document, purpose)
    with open(path + ".sig", "wb") as f:
        f.write(signature)


def verify_file(path: str, public_key: bytes, purpose: str = "general") -> bool:
    """
    Verify the detached signature stored at ``<path>.sig`` against the file at
    ``path``.  Returns ``True`` if the signature is valid, otherwise ``False``.
    """
    try:
        with open(path, "rb") as f:
            document = f.read()
        with open(path + ".sig", "rb") as f:
            signature = f.read()
    except FileNotFoundError:
        # Preserve the original behaviour of returning ``False`` when the
        # signature file is missing.
        return False

    return verify_document(public_key, document, signature, purpose)
