"""Signed webhooks, Stripe-style signature header. Post-quantum version (ML-DSA-65).

The sender signs "<timestamp>.<body>" with ML-DSA-65 (fixed context string) and sends
    X-Signature: t=<unix time>,v2=<base64 signature>
The receiver keeps one public key per signature scheme (dict scheme -> key), checks the
signature for its scheme and rejects messages older than `tolerance` seconds (replay window).
"""
import base64
import time

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SIG_ALG = "ML-DSA-65"
CONTEXT = b"pq-gate webhook v2"
SCHEME = "v2"


def generate_keypair():
    """Return (public_key, private_key) as bytes for the webhook sender."""
    with oqs.Signature(SIG_ALG) as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key


def sign_webhook(private_key, body, timestamp=None):
    """Return the X-Signature header value for `body` (bytes)."""
    ts = int(time.time() if timestamp is None else timestamp)
    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:
        signature = sig.sign_with_ctx_str(str(ts).encode() + b"." + body, CONTEXT)
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
        if "v1" in fields and "v1" in keys:  # senders that still sign with ECDSA
            serialization.load_pem_public_key(keys["v1"]).verify(
                base64.b64decode(fields["v1"]), str(ts).encode() + b"." + body,
                ec.ECDSA(hashes.SHA256()))
            now = time.time() if now is None else now
            return abs(now - ts) <= tolerance
        signature = base64.b64decode(fields[SCHEME])
        with oqs.Signature(SIG_ALG) as sig:
            if not sig.verify_with_ctx_str(str(ts).encode() + b"." + body, signature,
                                           CONTEXT, keys[SCHEME]):
                return False
    except Exception:
        return False
    now = time.time() if now is None else now
    return abs(now - ts) <= tolerance
