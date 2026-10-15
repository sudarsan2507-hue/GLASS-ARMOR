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
from cryptography.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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


def generate_hkdf_key(password, salt):
    """Generates an HKDF key from a password and salt."""
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=password)
    return kdf.derive(b"invoice")


def test_sign_verify_invoice():
    private_key, _ = generate_keypair()
    invoice = {"items": [{"qty": 2, "unit_cents": 100}, {"qty": 1, "unit_cents": 50}]}
    signed_invoice = sign_invoice(private_key, "Test Issuer", invoice)
    assert verify_invoice(signed_invoice["public_key"], signed_invoice)
    assert not verify_invoice(signed_invoice["public_key"], {"signature": "invalid"})


def test_sign_verify_credit_note():
    private_key, _ = generate_keypair()
    note = {"items": [{"qty": 1, "unit_cents": 25}]}
    signed_note = sign_credit_note(private_key, "Test Issuer", note)
    assert verify_credit_note(signed_note["public_key"], signed_note)
    assert not verify_credit_note(signed_note["public_key"], {"signature": "invalid"})


def test_hkdf_key_generation():
    password = b"secret_password"
    salt = os.urandom(32)
    hkdf_key = generate_hkdf_key(password, salt)
    assert len(hkdf_key) == 32
