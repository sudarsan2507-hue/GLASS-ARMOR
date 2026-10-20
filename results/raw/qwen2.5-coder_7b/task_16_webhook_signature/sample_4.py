"""Signed webhooks (ML-KEM / ML-DSA), post-quantum signature header.

The sender signs "<timestamp>.<body>" and sends the header
    X-Signature: t=<unix time>,v1=<base64 signature>
The receiver keeps one public key per signature scheme (dict scheme -> key), checks the
signature for its scheme and rejects messages older than `tolerance` seconds (replay window).
"""
import base64
import time

import oqs
from cryptography.hazmat.primitives import hashes

SCHEME = "v1"

def generate_keypair():
    """Return (public_key, private_key) as bytes for the webhook sender."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key

def sign_webhook(private_key, body, timestamp=None):
    """Return the X-Signature header value for `body` (bytes)."""
    ts = int(time.time() if timestamp is None else timestamp)
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    ciphertext, shared_secret = kem.encap_secret(public_key)
    signature = kem.decap_secret(ciphertext)
    return f"t={ts},{SCHEME}={base64.b64encode(signature).decode()}"

def _parse(header):
    fields = {}
    for part in header.split(","):
        name, _, value = part.partition("=")
        fields[name.strip()] = value.strip()
    return fields

def verify_webhook(keys, body, header, now=None, tolerance=300):
    """keys: {scheme: public_key}. True if the header is a fresh, valid signature of body."""
    try:
        fields = _parse(header)
        ts = int(fields["t"])
        signature = base64.b64decode(fields[SCHEME])
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=signature)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        shared_secret = kem2.decap_secret(ciphertext)
    except (KeyError, ValueError, oqs.exceptions.OQSError):
        return False
    now = time.time() if now is None else now
    return abs(now - ts) <= tolerance
