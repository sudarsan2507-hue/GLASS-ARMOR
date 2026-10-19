"""Signed e-invoices and credit notes (ML-KEM / ML-DSA).

An issuer signs an invoice (or a credit note) given as a dict. The signature covers a
canonical JSON encoding of the document plus a document-type label, so a signed credit
note can never be passed off as an invoice (and vice versa).
A signed document is the original dict plus "issuer" and "signature" (base64) fields.
"""
import base64
import json

from oqs import KeyEncapsulation, Signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for an issuer."""
    kem = KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()            # bytes
    secret_key = kem.export_secret_key()           # bytes
    return public_key, secret_key


def _canonical(doc, issuer):
    body = {k: v for k, v in doc.items() if k not in ("issuer", "signature")}
    return json.dumps({"issuer": issuer, "doc": body}, sort_keys=True, separators=(",", ":")).encode()


def _sign(private_key, doc_type, issuer, doc):
    kem = KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    ciphertext, shared_secret = kem.encap_secret(public_key)
    signature = oqs.Signature("ML-DSA-65").sign(doc_type + b"|" + _canonical(doc, issuer), shared_secret)
    return dict(doc, issuer=issuer, signature=base64.b64encode(signature).decode())


def _verify(public_key, doc_type, signed):
    try:
        kem = KeyEncapsulation("ML-KEM-768", public_key=public_key)
        shared_secret = kem.decap_secret(ciphertext)
        key = oqs.Signature("ML-DSA-65")
        key.verify(base64.b64decode(signed["signature"]),
                   doc_type + b"|" + _canonical(signed, signed["issuer"]), shared_secret)
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
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
