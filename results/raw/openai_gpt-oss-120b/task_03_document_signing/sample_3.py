"""Document signing service (ML‑DSA‑65, post‑quantum).

A signature covers a purpose label (e.g. "contract", "invoice") together with the
document, so a signature made for one purpose is not valid for another.
Detached signatures for files are stored next to the file as <path>.sig.
"""

import oqs
from cryptography.exceptions import InvalidSignature  # kept for backward compatibility


def _signed_bytes(document: bytes, purpose: str) -> bytes:
    """Create the canonical byte representation that is signed."""
    return b"pq-gate docsign v1|" + purpose.encode() + b"|" + document


# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
def generate_keypair():
    """
    Return ``(public_key, private_key)`` as ``bytes`` for a signer.

    The keys are generated with the post‑quantum signature scheme
    **ML‑DSA‑65** provided by liboqs.  The returned values are the raw
    byte strings produced by liboqs (not PEM encoded).
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Signing / verification (in‑memory)
# --------------------------------------------------------------------------- #
def sign_document(private_key: bytes, document: bytes, purpose: str = "general") -> bytes:
    """
    Sign *document* for the given *purpose* using the supplied *private_key*.
    Returns the raw signature bytes.
    """
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    return signer.sign(_signed_bytes(document, purpose))


def verify_document(public_key: bytes, document: bytes, signature: bytes,
                    purpose: str = "general") -> bool:
    """
    Return ``True`` if *signature* is a valid signature for *document* and
    *purpose* under *public_key*, otherwise ``False``.
    """
    verifier = oqs.Signature("ML-DSA-65")
    try:
        # liboqs returns a boolean; we also guard against unexpected exceptions.
        return verifier.verify(_signed_bytes(document, purpose), signature, public_key)
    except Exception:  # pragma: no cover – defensive, liboqs shouldn't raise here
        return False


# --------------------------------------------------------------------------- #
# Signing / verification (files)
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
    try:
        with open(path + ".sig", "rb") as f:
            signature = f.read()
    except FileNotFoundError:
        return False
    return verify_document(public_key, document, signature, purpose)
