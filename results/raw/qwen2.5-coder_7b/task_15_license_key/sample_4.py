"""Offline software license keys (ML-KEM / ML-DSA).

The vendor signs {customer, product, expires, seats}. The license string is
"LIC1-" + base32(2-byte payload length | payload JSON | signature), so it can be
pasted into the app. The app checks the signature, the product name and the expiry date.
"""
import base64
import datetime
import json
import struct

from oqs import Signature
from oqs import KeyEncapsulation

PREFIX = "LIC1-"

def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the vendor."""
    kem = KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()            # bytes
    secret_key = kem.export_secret_key()           # bytes
    return public_key, secret_key

def _payload(customer, product, expires, seats):
    return json.dumps({"customer": customer, "product": product, "expires": expires,
                       "seats": seats}, sort_keys=True).encode()

def issue_license(public_key, customer, product, expires, seats=1):
    """expires is an ISO date string, e.g. "2027-12-31". Returns the license string."""
    payload = _payload(customer, product, expires, seats)
    sig = Signature("ML-DSA-65")
    signature = sig.sign(payload)
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
        sig = Signature("ML-DSA-65")
        sig.verify(signature, payload)
        info = json.loads(payload)
    except (ValueError, struct.error, InvalidSignature):
        return None
    today = today or datetime.date.today()
    if info["product"] != product or datetime.date.fromisoformat(info["expires"]) < today:
        return None
    return info
