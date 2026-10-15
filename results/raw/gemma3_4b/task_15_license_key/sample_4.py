"""Offline software license keys (ECDSA P-256).

The vendor signs {customer, product, expires, seats}. The license string is
"LIC1-" + base32(2-byte payload length | payload JSON | signature), so it can be
pasted into the app. The app checks the signature, the product name and the expiry date.
"""
import base64
import datetime
import json
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PREFIX = "LIC1-"


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the vendor."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return public_bytes, private_bytes


def _payload(customer, product, expires, seats=1):
    return json.dumps({"customer": customer, "product": product, "expires": expires,
                       "seats": seats}, sort_keys=True).encode()


def issue_license(private_key, customer, product, expires, seats=1):
    """expires is an ISO date string, e.g. "2027-12-31". Returns the license string."""
    payload = _payload(customer, product, expires, seats)
    key = serialization.load_pem_private_key(private_key, password=None)
    signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
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
        serialization.load_pem_public_key(public_key).verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        info = json.loads(payload)
    except (ValueError, struct.error, InvalidSignature):
        return None
    today = today or datetime.date.today()
    if info["product"] != product or datetime.date.fromisoformat(info["expires"]) < today:
        return None
    return info


# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
shared_secret = kem2.decap_secret(ciphertext)  # 32 bytes
# ML-DSA-65
sig = oqs.Signature("ML-DSA-65")
public_key = sig.generate_keypair()
secret_key = sig.export_secret_key()
signature = oqs.Signature("ML-DSA-65", secret_key=secret_key).sign(message)
ok = oqs.Signature("ML-DSA-65").verify(message, signature, public_key)  # bool
signature = sig.sign_with_ctx_str(message, context)
ok = oqs.Signature("ML-DSA-65").verify_with_ctx_str(message, signature, context, public_key)
# HKDF (cryptography)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"...").derive(input_bytes)
