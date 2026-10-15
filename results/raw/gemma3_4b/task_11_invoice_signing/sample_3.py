"""Signed e-invoices and credit notes (ECDSA P-256).

An issuer signs an invoice (or a credit note) given as a dict. The signature covers a
canonical JSON encoding of the document plus a document-type label, so a signed credit
note can never be passed off as an invoice (and vice versa).
A signed document is the original dict plus "issuer" and "signature" (base64) fields.
"""
import base64
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for an issuer."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return public_bytes, private_bytes


def _canonical(doc, issuer):
    body = {k: v for k, v in doc.items() if k not in ("issuer", "signature")}
    return json.dumps({"issuer": issuer, "doc": body}, sort_keys=True, separators=(",", ":")).encode()


def _sign(private_key, doc_type, issuer, doc):
    key = serialization.load_pem_private_key(private_key, password=None)
    signature = key.sign(doc_type + b"|" + _canonical(doc, issuer), ec.ECDSA(hashes.SHA256()))
    return dict(doc, issuer=issuer, signature=base64.b64encode(signature).decode())


def _verify(public_key, doc_type, signed):
    try:
        key = serialization.load_pem_public_key(public_key)
        key.verify(base64.b64decode(signed["signature"]),
                   doc_type + b"|" + _canonical(signed, signed["issuer"]), ec.ECDSA(hashes.SHA256()))
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


def generate_keypair_oqs():
    """Return (public_key, private_key) as bytes for an issuer using liboqs."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key, private_key = kem.generate_keypair()
    return public_key, private_key


def sign_invoice_oqs(private_key):
    """Sign an invoice using liboqs."""
    sig = oqs.Signature("ML-DSA-65", secret_key=private_key)
    message = b"invoice-v1|" + b"{" + json.dumps({"qty": 1, "unit_cents": 100}, sort_keys=True).encode() + b"}"
    signature = sig.sign(message)
    return signature


def verify_invoice_oqs(public_key, signature, message):
    """Verify an invoice using liboqs."""
    sig = oqs.Signature("ML-DSA-65", public_key=public_key)
    try:
        ok = sig.verify(message, signature)
        return ok
    except InvalidSignature:
        return False


def sign_credit_note_oqs(private_key):
    """Sign a credit note using liboqs."""
    sig = oqs.Signature("ML-DSA-65", secret_key=private_key)
    message = b"credit-note-v1|" + b"{" + json.dumps({"qty": 1, "unit_cents": 100}, sort_keys=True).encode() + b"}"
    signature = sig.sign(message)
    return signature


def verify_credit_note_oqs(public_key, signature, message):
    """Verify a credit note using liboqs."""
    sig = oqs.Signature("ML-DSA-65", public_key=public_key)
    try:
        ok = sig.verify(message, signature)
        return ok
    except InvalidSignature:
        return False
