"""Offline software license keys. Post-quantum version (ML-DSA-65).

The vendor signs {customer, product, expires, seats} with ML-DSA-65 (fixed context string).
The license string is "LIC2-" + base32(2-byte payload length | payload JSON | signature),
so it can be pasted into the app. The app checks the signature, the product name and the
expiry date.
"""
import base64
import datetime
import json
import struct

import oqs

SIG_ALG = "ML-DSA-65"
CONTEXT = b"pq-gate license v2"
PREFIX = "LIC2-"


def generate_keypair():
    """Return (public_key, private_key) as bytes for the vendor."""
    with oqs.Signature(SIG_ALG) as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key


def _payload(customer, product, expires, seats):
    return json.dumps({"customer": customer, "product": product, "expires": expires,
                       "seats": seats}, sort_keys=True).encode()


def issue_license(private_key, customer, product, expires, seats=1):
    """expires is an ISO date string, e.g. "2027-12-31". Returns the license string."""
    payload = _payload(customer, product, expires, seats)
    try:
        with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:
            signature = sig.sign_with_ctx_str(payload, CONTEXT)
    except Exception as e:
        raise RuntimeError(f"could not sign license with vendor key {private_key!r}") from e
    raw = struct.pack(">H", len(payload)) + payload + signature
    return PREFIX + base64.b32encode(raw).decode().rstrip("=")


def verify_license(public_key, license_key, product, today=None):
    """Return the license dict if valid for `product` on `today` (a date), else None."""
    if not license_key.startswith(PREFIX):
        return None
    try:
        body = license_key[len(PREFIX):]
        raw = base64.b32decode(body + "=" * (-len(body) % 8))
        (n,) = struct.unpack(">H", raw[:2])
        payload, signature = raw[2:2 + n], raw[2 + n:]
        with oqs.Signature(SIG_ALG) as sig:
            if not sig.verify_with_ctx_str(payload, signature, CONTEXT, public_key):
                return None
        info = json.loads(payload)
    except Exception:
        return None
    today = today or datetime.date.today()
    if info["product"] != product or datetime.date.fromisoformat(info["expires"]) < today:
        return None
    return info
