"""Document signing service (ML‑DSA‑65 – post‑quantum).

A signature covers a purpose label (e.g. "contract", "invoice") together with the
document, so a signature made for one purpose is not valid for another.
Detached signatures for files are stored next to the file as <path>.sig.

The public API (generate_keypair, sign_document, verify_document, sign_file,
verify_file) is unchanged, so existing tests continue to work.
"""

from __future__ import annotations

import oqs
from cryptography.exceptions import InvalidSignature  # kept for compatibility


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _signed_bytes(document: bytes, purpose: str) -> bytes:
    """
    Construct the byte sequence that is actually signed / verified.

    The format mirrors the original RSA‑PSS implementation so that the same
    purpose‑specific data is covered by the signature.
    """
    return b"pq-gate docsign v1|" + purpose.encode() + b"|" + document


# --------------------------------------------------------------------------- #
# Public API – key generation
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[bytes, bytes]:
    """
    Return ``(public_key, private_key)`` as PEM‑like byte strings for a signer.

    Internally this uses the post‑quantum signature scheme **ML‑DSA‑65** from
    liboqs.  The returned ``private_key`` is the raw secret key bytes exported by
    liboqs; the ``public_key`` is the corresponding public key bytes.
    """
    # Create a temporary Signature object to generate a fresh key pair.
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    # Clean up the temporary object (frees native resources).
    sig.free()
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Public API – signing / verification
# --------------------------------------------------------------------------- #
def sign_document(private_key: bytes, document: bytes, purpose: str = "general") -> bytes:
    """
    Sign *document* for the given *purpose* using the supplied *private_key*.

    The function returns the raw signature bytes produced by ML‑DSA‑65.
    """
    # Initialise a Signature object with the provided secret key.
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
    Return ``True`` if *signature* is a valid ML‑DSA‑65 signature for *document*
    and *purpose* using *public_key*, otherwise ``False``.
    """
    verifier = oqs.Signature("ML-DSA-65")
    try:
        # ``verify`` returns ``True``/``False``; it does not raise.
        return verifier.verify(_signed_bytes(document, purpose), signature, public_key)
    finally:
        verifier.free()


# --------------------------------------------------------------------------- #
# Public API – file helpers
# --------------------------------------------------------------------------- #
def sign_file(path: str, private_key: bytes, purpose: str = "general") -> None:
    """
    Sign the file at *path* and write the signature to ``<path>.sig``.
    """
    with open(path, "rb") as f:
        document = f.read()
    signature = sign_document(private_key, document, purpose)
    with open(path + ".sig", "wb") as f:
        f.write(signature)


def verify_file(path: str, public_key: bytes, purpose: str = "general") -> bool:
    """
    Verify the signature stored in ``<path>.sig`` against the file at *path*.
    Returns ``True`` if the signature is valid, otherwise ``False``.
    """
    with open(path, "rb") as f:
        document = f.read()
    with open(path + ".sig", "rb") as f:
        signature = f.read()
    return verify_document(public_key, document, signature, purpose)
