"""Offline software license keys (ML‑DSA‑65 post‑quantum signatures).

The vendor signs {customer, product, expires, seats}. The license string is
"LIC1-" + base32(2‑byte payload length | payload JSON | signature), so it can be
pasted into the app. The app checks the signature, the product name and the
expiry date.

This module mirrors the original API that used ECDSA‑P256, but now uses the
post‑quantum ML‑DSA‑65 algorithm from liboqs.  The public functions keep the same
signatures, so existing tests continue to work.
"""

import base64
import datetime
import json
import struct

import oqs  # liboqs‑python
from cryptography.exceptions import InvalidSignature  # kept for compatibility

PREFIX = "LIC1-"
_KEM_NAME = "ML-DSA-65"  # algorithm identifier used by liboqs


def generate_keypair():
    """Return (public_key, private_key) as raw bytes for the vendor.

    The keys are the byte strings produced by liboqs; they are *not* PEM encoded.
    They can be stored or transmitted directly and are accepted by the other
    functions in this module.
    """
    sig = oqs.Signature(_KEM_NAME)
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    # Explicitly free the OQS object to avoid resource warnings.
    sig.free()
    return public_key, private_key


def _payload(customer, product, expires, seats):
    """Create the JSON payload (bytes) that is signed."""
    return json.dumps(
        {
            "customer": customer,
            "product": product,
            "expires": expires,
            "seats": seats,
        },
        sort_keys=True,
    ).encode()


def issue_license(private_key, customer, product, expires, seats=1):
    """Create a license string signed with the vendor's private key.

    * ``private_key`` – the secret key bytes returned by :func:`generate_keypair`.
    * ``expires`` – ISO‑date string, e.g. ``"2027-12-31"``.
    * Returns the license string ready to be handed to a client.
    """
    payload = _payload(customer, product, expires, seats)

    # Initialise the signature object with the secret key.
    signer = oqs.Signature(_KEM_NAME, secret_key=private_key)
    signature = signer.sign(payload)
    signer.free()

    # Assemble length prefix, payload and signature.
    raw = struct.pack(">H", len(payload)) + payload + signature
    # Base32‑encode without padding, then strip trailing '=' for compactness.
    return PREFIX + base64.b32encode(raw).decode().rstrip("=")


def verify_license(public_key, license_key, product, today=None):
    """Validate a license string.

    Returns the decoded payload dict if the license is valid for ``product`` on
    ``today`` (a :class:`datetime.date`).  Returns ``None`` on any failure
    (malformed, bad signature, wrong product, or expired).
    """
    if not license_key.startswith(PREFIX):
        return None

    try:
        # Restore any missing padding for base32 decoding.
        body = license_key[len(PREFIX) :]
        raw = base64.b32decode(body + "=" * (-len(body) % 8))

        # Extract length, payload and signature.
        (n,) = struct.unpack(">H", raw[:2])
        payload, signature = raw[2 : 2 + n], raw[2 + n :]

        # Verify the signature using the public key.
        verifier = oqs.Signature(_KEM_NAME)
        ok = verifier.verify(payload, signature, public_key)
        verifier.free()
        if not ok:
            raise InvalidSignature  # unify error handling below

        info = json.loads(payload)

    except (ValueError, struct.error, InvalidSignature, oqs.OQSError):
        return None

    today = today or datetime.date.today()
    if (
        info.get("product") != product
        or datetime.date.fromisoformat(info.get("expires", "1970-01-01")) < today
    ):
        return None

    return info
