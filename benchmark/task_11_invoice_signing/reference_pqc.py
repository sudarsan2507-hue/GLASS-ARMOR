"""Signed e-invoices and credit notes. Post-quantum version (ML-DSA-65).

An issuer signs an invoice (or a credit note) given as a dict. The signature covers a
canonical JSON encoding of the document; the document-type label is the ML-DSA context
string, so a signed credit note can never be passed off as an invoice (and vice versa).
A signed document is the original dict plus "issuer" and "signature" (base64) fields.
"""
import base64
import json

import oqs

SIG_ALG = "ML-DSA-65"


def generate_keypair():
    """Return (public_key, private_key) as bytes for an issuer."""
    with oqs.Signature(SIG_ALG) as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key


def _canonical(doc, issuer):
    body = {k: v for k, v in doc.items() if k not in ("issuer", "signature")}
    return json.dumps({"issuer": issuer, "doc": body}, sort_keys=True, separators=(",", ":")).encode()


def _sign(private_key, doc_type, issuer, doc):
    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:
        signature = sig.sign_with_ctx_str(_canonical(doc, issuer), doc_type)
    return dict(doc, issuer=issuer, signature=base64.b64encode(signature).decode())


def _verify(public_key, doc_type, signed):
    try:
        with oqs.Signature(SIG_ALG) as sig:
            return sig.verify_with_ctx_str(_canonical(signed, signed["issuer"]),
                                           base64.b64decode(signed["signature"]), doc_type, public_key)
    except Exception:
        return False


def sign_invoice(private_key, issuer, invoice):
    return _sign(private_key, b"invoice-v1", issuer, invoice)


def verify_invoice(public_key, signed_invoice):
    return _verify(public_key, b"invoice-v1", signed_invoice)


def sign_credit_note(private_key, issuer, note):
    return _sign(private_key, b"credit-note-v1", issuer, note)


def verify_credit_note(public_key, signed_note):
    return _verify(public_key, b"credit-note-v1", signed_note)


def invoice_total(invoice):
    """Sum of quantity * unit price (in cents) over all lines."""
    return sum(line["qty"] * line["unit_cents"] for line in invoice["lines"])
