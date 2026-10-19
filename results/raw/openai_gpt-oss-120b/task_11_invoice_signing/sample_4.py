"""Signed e‑invoices and credit notes (ML‑DSA‑65).

An issuer signs an invoice (or a credit note) given as a dict. The signature covers a
canonical JSON encoding of the document plus a document‑type label, so a signed credit
note can never be passed off as an invoice (and vice versa).

A signed document is the original dict plus "issuer" and "signature" (base64) fields.
The implementation now uses post‑quantum signatures (ML‑DSA‑65) via liboqs, while
preserving the original public API.
"""
import base64
import json

import oqs
from cryptography.exceptions import InvalidSignature  # kept for backward compatibility


def generate_keypair():
    """Return (public_key, private_key) as raw bytes for an issuer.

    The keys are generated with the ML‑DSA‑65 algorithm.  The public key is suitable
    for distribution, while the private key must be kept secret.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    return public_key, private_key


def _canonical(doc, issuer):
    """Create a deterministic JSON representation of *doc* without signature data."""
    body = {k: v for k, v in doc.items() if k not in ("issuer", "signature")}
    return json.dumps(
        {"issuer": issuer, "doc": body},
        sort_keys=True,
        separators=(",", ":")
    ).encode()


def _sign(private_key, doc_type, issuer, doc):
    """Sign *doc* with the given private key and document type.

    The signature is produced with ML‑DSA‑65 and returned as a base64‑encoded string
    inside a copy of *doc* that also contains the ``issuer`` field.
    """
    # Initialise a Signature object that knows the secret key
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)

    # Message format matches the original implementation
    message = doc_type + b"|" + _canonical(doc, issuer)

    signature = signer.sign(message)                     # raw bytes
    b64_sig = base64.b64encode(signature).decode()

    # Return a new dict that includes the issuer and the base64 signature
    signed = dict(doc, issuer=issuer, signature=b64_sig)
    return signed


def _verify(public_key, doc_type, signed):
    """Verify a signed document using the supplied public key.

    Returns ``True`` if the signature is valid, ``False`` otherwise.
    """
    try:
        verifier = oqs.Signature("ML-DSA-65")
        message = doc_type + b"|" + _canonical(signed, signed["issuer"])
        signature = base64.b64decode(signed["signature"])
        return verifier.verify(message, signature, public_key)
    except (InvalidSignature, ValueError, KeyError, TypeError):
        # ``InvalidSignature`` is kept for compatibility with the old API;
        # liboqs raises ``False`` rather than an exception, but we guard against
        # malformed inputs.
        return False


def sign_invoice(private_key, issuer, invoice):
    """Create a signed invoice."""
    return _sign(private_key, b"invoice-v1", issuer, invoice)


def verify_invoice(public_key, signed_invoice):
    """Validate a signed invoice."""
    return _verify(public_key, b"invoice-v1", signed_invoice)


def sign_credit_note(private_key, issuer, note):
    """Create a signed credit note."""
    return _sign(private_key, b"credit-note-v1", issuer, note)


def verify_credit_note(public_key, signed_note):
    """Validate a signed credit note."""
    return _verify(public_key, b"credit-note-v1", signed_note)


def invoice_total(invoice):
    """Sum of quantity * unit price (in cents) over all lines."""
    return sum(line["qty"] * line["unit_cents"] for line in invoice["lines"])
