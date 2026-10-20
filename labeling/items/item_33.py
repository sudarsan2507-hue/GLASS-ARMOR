"""Signed e-invoices and credit notes (ML‑DSA‑65 post‑quantum signatures).

An issuer signs an invoice (or a credit note) given as a dict. The signature
covers a canonical JSON encoding of the document plus a document‑type label,
so a signed credit note can never be passed off as an invoice (and vice
versa).

A signed document is the original dict plus "issuer" and "signature"
(base64) fields.
"""
import base64
import json

import oqs  # liboqs‑python
from cryptography.exceptions import InvalidSignature  # kept for backward compatibility


# --------------------------------------------------------------------------- #
# Key handling (ML‑DSA‑65)
# --------------------------------------------------------------------------- #
def generate_keypair():
    """Return (public_key, private_key) as raw bytes for an issuer.

    The keys are generated with the ML‑DSA‑65 algorithm (post‑quantum
    signature).  They are returned as raw byte strings – callers should
    treat them as opaque values.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _canonical(doc, issuer):
    """Return a deterministic JSON representation of *doc* (without signature)."""
    body = {k: v for k, v in doc.items() if k not in ("issuer", "signature")}
    return json.dumps(
        {"issuer": issuer, "doc": body},
        sort_keys=True,
        separators=(",", ":")
    ).encode()


def _sign(private_key, doc_type, issuer, doc):
    """Create a ML‑DSA‑65 signature over the document."""
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    message = doc_type + b"|" + _canonical(doc, issuer)
    signature = signer.sign(message)                     # bytes
    return dict(doc, issuer=issuer,
                signature=base64.b64encode(signature).decode())


def _verify(public_key, doc_type, signed):
    """Verify a ML‑DSA‑65 signature; return ``True`` on success."""
    try:
        verifier = oqs.Signature("ML-DSA-65")
        message = doc_type + b"|" + _canonical(signed, signed["issuer"])
        sig_bytes = base64.b64decode(signed["signature"])
        return verifier.verify(message, sig_bytes, public_key)
    except (InvalidSignature, ValueError, KeyError, TypeError, Exception):
        # ``InvalidSignature`` is kept for compatibility with the old API.
        return False


# --------------------------------------------------------------------------- #
# Public API (unchanged signatures)
# --------------------------------------------------------------------------- #
def sign_invoice(private_key, issuer, invoice):
    """Sign an invoice dict."""
    return _sign(private_key, b"invoice-v1", issuer, invoice)


def verify_invoice(public_key, signed_invoice):
    """Verify a signed invoice dict."""
    return _verify(public_key, b"invoice-v1", signed_invoice)


def sign_credit_note(private_key, issuer, note):
    """Sign a credit‑note dict."""
    return _sign(private_key, b"credit-note-v1", issuer, note)


def verify_credit_note(public_key, signed_note):
    """Verify a signed credit‑note dict."""
    return _verify(public_key, b"credit-note-v1", signed_note)


def invoice_total(invoice):
    """Sum of quantity * unit price (in cents) over all lines."""
    return sum(line["qty"] * line["unit_cents"] for line in invoice["lines"])
