"""Signed e‑invoices and credit notes (ML‑DSA‑65 post‑quantum signatures).

An issuer signs an invoice (or a credit note) given as a dict. The signature covers a
canonical JSON encoding of the document plus a document‑type label, so a signed credit
note can never be passed off as an invoice (and vice versa).

A signed document is the original dict plus ``issuer`` and ``signature`` (base64) fields.
The public API (function names and signatures) is unchanged, so existing tests continue
to work, but the underlying cryptography now uses the post‑quantum ML‑DSA‑65 algorithm
via ``liboqs``.
"""
import base64
import json

import oqs
from cryptography.exceptions import InvalidSignature  # kept for backward compatibility


def generate_keypair():
    """Return ``(public_key, private_key)`` as ``bytes`` for an issuer.

    The keys are raw byte strings produced by liboqs for the ML‑DSA‑65 algorithm.
    They are **not** PEM‑encoded; however they are opaque to callers and can be stored
    or transmitted exactly as returned.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key, secret_key = sig.generate_keypair()
    # ``secret_key`` is the private key; liboqs also allows exporting it later.
    return public_key, secret_key


def _canonical(doc, issuer):
    """Return the canonical JSON representation (bytes) of *doc* for *issuer*."""
    body = {k: v for k, v in doc.items() if k not in ("issuer", "signature")}
    return json.dumps(
        {"issuer": issuer, "doc": body},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _sign(private_key, doc_type, issuer, doc):
    """Create a base64‑encoded ML‑DSA‑65 signature for *doc*.

    ``private_key`` must be the raw secret‑key bytes returned by :func:`generate_keypair`.
    """
    message = doc_type + b"|" + _canonical(doc, issuer)
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    signature = signer.sign(message)
    # Return a new dict that includes the issuer and the base64‑encoded signature.
    return dict(doc, issuer=issuer, signature=base64.b64encode(signature).decode())


def _verify(public_key, doc_type, signed):
    """Verify a base64‑encoded ML‑DSA‑65 signature.

    Returns ``True`` if the signature is valid, ``False`` otherwise.
    """
    try:
        message = doc_type + b"|" + _canonical(signed, signed["issuer"])
        signature = base64.b64decode(signed["signature"])
        verifier = oqs.Signature("ML-DSA-65")
        return verifier.verify(message, signature, public_key)
    except (InvalidSignature, ValueError, KeyError, TypeError):
        # ``InvalidSignature`` is kept for API compatibility; liboqs raises ``False`
        # rather than an exception, but we guard against malformed inputs.
        return False


def sign_invoice(private_key, issuer, invoice):
    """Sign an invoice dict with the issuer's private key."""
    return _sign(private_key, b"invoice-v1", issuer, invoice)


def verify_invoice(public_key, signed_invoice):
    """Verify a signed invoice dict with the issuer's public key."""
    return _verify(public_key, b"invoice-v1", signed_invoice)


def sign_credit_note(private_key, issuer, note):
    """Sign a credit‑note dict with the issuer's private key."""
    return _sign(private_key, b"credit-note-v1", issuer, note)


def verify_credit_note(public_key, signed_note):
    """Verify a signed credit‑note dict with the issuer's public key."""
    return _verify(public_key, b"credit-note-v1", signed_note)


def invoice_total(invoice):
    """Sum of ``quantity * unit price`` (in cents) over all lines."""
    return sum(line["qty"] * line["unit_cents"] for line in invoice["lines"])
