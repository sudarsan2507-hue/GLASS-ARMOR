"""Signed e‑invoices and credit notes (ML‑DSA‑65, post‑quantum).

An issuer signs an invoice (or a credit note) given as a dict. The signature covers a
canonical JSON encoding of the document plus a document‑type label, so a signed credit
note can never be passed off as an invoice (and vice‑versa).

A signed document is the original dict plus ``issuer`` and ``signature`` (base64) fields.
The implementation now uses the post‑quantum ML‑DSA‑65 algorithm from liboqs, keeping the
same public API as the original ECDSA‑based version.
"""
import base64
import json

import oqs

# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _canonical(doc: dict, issuer: str) -> bytes:
    """
    Produce a deterministic byte representation of *doc* (excluding any existing
    ``issuer`` or ``signature`` fields) together with the *issuer* identifier.
    """
    body = {k: v for k, v in doc.items() if k not in ("issuer", "signature")}
    # The JSON string is compact (no whitespace) and keys are sorted.
    return json.dumps(
        {"issuer": issuer, "doc": body},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _sign(private_key: bytes, doc_type: bytes, issuer: str, doc: dict) -> dict:
    """
    Sign *doc* with the given *private_key* (ML‑DSA‑65 secret key bytes).

    The signature is computed over ``doc_type + b"|" + _canonical(doc, issuer)``.
    The resulting dict contains the original fields plus ``issuer`` and a base64
    encoded ``signature`` field.
    """
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    message = doc_type + b"|" + _canonical(doc, issuer)
    signature = signer.sign(message)
    # Encode the raw signature bytes as base64 for JSON friendliness.
    return dict(doc, issuer=issuer, signature=base64.b64encode(signature).decode())


def _verify(public_key: bytes, doc_type: bytes, signed: dict) -> bool:
    """
    Verify a signed document using the supplied *public_key* (ML‑DSA‑65 public key bytes).

    Returns ``True`` if the signature is valid, ``False`` otherwise.
    """
    try:
        verifier = oqs.Signature("ML-DSA-65")
        message = doc_type + b"|" + _canonical(signed, signed["issuer"])
        signature = base64.b64decode(signed["signature"])
        return verifier.verify(message, signature, public_key)
    except Exception:  # liboqs raises generic exceptions on failure
        return False


# --------------------------------------------------------------------------- #
# Public API (unchanged signatures)
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a new ML‑DSA‑65 key pair.

    Returns a tuple ``(public_key, private_key)`` where both elements are raw
    byte strings as produced by liboqs.  The format is compatible with the
    ``oqs.Signature`` class and can be stored or transmitted directly.
    """
    signer = oqs.Signature("ML-DSA-65")
    public_key = signer.generate_keypair()
    private_key = signer.export_secret_key()
    return public_key, private_key


def sign_invoice(private_key: bytes, issuer: str, invoice: dict) -> dict:
    """Sign an invoice dict."""
    return _sign(private_key, b"invoice-v1", issuer, invoice)


def verify_invoice(public_key: bytes, signed_invoice: dict) -> bool:
    """Verify a signed invoice dict."""
    return _verify(public_key, b"invoice-v1", signed_invoice)


def sign_credit_note(private_key: bytes, issuer: str, note: dict) -> dict:
    """Sign a credit‑note dict."""
    return _sign(private_key, b"credit-note-v1", issuer, note)


def verify_credit_note(public_key: bytes, signed_note: dict) -> bool:
    """Verify a signed credit‑note dict."""
    return _verify(public_key, b"credit-note-v1", signed_note)


def invoice_total(invoice: dict) -> int:
    """Sum of ``quantity * unit price`` (in cents) over all lines."""
    return sum(line["qty"] * line["unit_cents"] for line in invoice["lines"])
