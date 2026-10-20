"""Offline software license keys (ML‑DSA‑65 post‑quantum signatures).

The vendor signs {customer, product, expires, seats}. The license string is
"LIC1-" + base32(2‑byte payload length | payload JSON | signature), so it can be
pasted into the app. The app checks the signature, the product name and the
expiry date.

The implementation now uses liboqs (ML‑DSA‑65) instead of ECDSA‑P‑256, but the
public API (`generate_keypair`, `issue_license`, `verify_license`) is unchanged,
so existing tests continue to work.
"""
import base64
import datetime
import json
import struct

import oqs  # liboqs‑python
from cryptography.exceptions import InvalidSignature  # kept for backward‑compatibility import

# --------------------------------------------------------------------------- #
# Public constants
# --------------------------------------------------------------------------- #
PREFIX = "LIC1-"

# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _payload(customer: str, product: str, expires: str, seats: int) -> bytes:
    """Return the canonical JSON payload as UTF‑8 bytes."""
    return json.dumps(
        {
            "customer": customer,
            "product": product,
            "expires": expires,
            "seats": seats,
        },
        sort_keys=True,
    ).encode()


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def generate_keypair():
    """Return ``(public_key, private_key)`` as raw bytes for the vendor.

    The keys are generated with the ML‑DSA‑65 algorithm provided by liboqs.
    """
    signer = oqs.Signature("ML-DSA-65")
    public_key = signer.generate_keypair()          # bytes
    private_key = signer.export_secret_key()        # bytes
    return public_key, private_key


def issue_license(private_key: bytes, customer: str, product: str, expires: str, seats: int = 1) -> str:
    """Create a license string signed with the vendor's *private_key*.

    ``expires`` must be an ISO‑8601 date string, e.g. ``"2027-12-31"``.
    The returned value is a string ready to be stored or transmitted.
    """
    payload = _payload(customer, product, expires, seats)

    # Sign with ML‑DSA‑65
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    signature = signer.sign(payload)                # bytes

    # Assemble: length (2 bytes, big‑endian) + payload + signature
    raw = struct.pack(">H", len(payload)) + payload + signature
    # Base‑32 encode, strip padding, prepend prefix
    return PREFIX + base64.b32encode(raw).decode().rstrip("=")


def verify_license(public_key: bytes, license_key: str, product: str, today: datetime.date | None = None):
    """Validate *license_key* and return the decoded payload dict or ``None``.

    The function checks:
      * correct prefix,
      * successful ML‑DSA‑65 signature verification,
      * that the embedded ``product`` matches the expected one,
      * that the licence has not expired (relative to ``today`` or ``date.today()``).

    On any failure ``None`` is returned.
    """
    if not license_key.startswith(PREFIX):
        return None

    try:
        # Decode the base‑32 body (add padding if necessary)
        body = license_key[len(PREFIX) :]
        raw = base64.b32decode(body + "=" * (-len(body) % 8))

        # Extract length, payload and signature
        (payload_len,) = struct.unpack(">H", raw[:2])
        payload = raw[2 : 2 + payload_len]
        signature = raw[2 + payload_len :]

        # Verify the signature with liboqs
        verifier = oqs.Signature("ML-DSA-65")
        if not verifier.verify(payload, signature, public_key):
            return None

        info = json.loads(payload)

    except (ValueError, struct.error, json.JSONDecodeError, InvalidSignature):
        # ``InvalidSignature`` is kept for compatibility with the old import path.
        return None

    # Date checks
    today = today or datetime.date.today()
    if (
        info.get("product") != product
        or datetime.date.fromisoformat(info.get("expires", "1970-01-01")) < today
    ):
        return None

    return info
