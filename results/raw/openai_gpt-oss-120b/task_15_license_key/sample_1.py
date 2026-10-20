"""Offline software license keys (ML‑DSA‑65 post‑quantum signature).

The vendor signs {customer, product, expires, seats}. The license string is
"LIC1-" + base32(2‑byte payload length | payload JSON | signature), so it can be
pasted into the app. The app checks the signature, the product name and the
expiry date.

The implementation now uses liboqs (ML‑DSA‑65) instead of classical ECDSA,
while keeping the original public API so existing tests continue to pass.
"""
import base64
import datetime
import json
import struct
from typing import Tuple

import oqs

# --------------------------------------------------------------------------- #
# PEM helpers – we wrap the raw OQS keys in a simple PEM‑like format so that
# callers can continue to treat them as “bytes” just like before.
# --------------------------------------------------------------------------- #
_PEM_PUBLIC_HEADER = b"-----BEGIN OQS PUBLIC KEY-----\n"
_PEM_PUBLIC_FOOTER = b"\n-----END OQS PUBLIC KEY-----"
_PEM_PRIVATE_HEADER = b"-----BEGIN OQS PRIVATE KEY-----\n"
_PEM_PRIVATE_FOOTER = b"\n-----END OQS PRIVATE KEY-----"


def _pem_encode(raw: bytes, header: bytes, footer: bytes) -> bytes:
    """Encode raw key bytes into a PEM‑like block."""
    b64 = base64.b64encode(raw)
    # split into 64‑char lines (standard PEM style)
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return header + b"\n".join(lines) + footer


def _pem_decode(pem: bytes, header: bytes, footer: bytes) -> bytes:
    """Extract raw key bytes from a PEM‑like block."""
    if not (pem.startswith(header) and pem.rstrip().endswith(footer)):
        raise ValueError("Invalid PEM format")
    # Strip header/footer and any surrounding whitespace / newlines
    body = pem[len(header) : -len(footer)].strip()
    # Remove any internal newlines and decode
    return base64.b64decode(b"".join(body.split()))


# --------------------------------------------------------------------------- #
# Public API (unchanged signature)
# --------------------------------------------------------------------------- #
PREFIX = "LIC1-"


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Return ``(public_key, private_key)`` as PEM‑encoded bytes for the vendor.

    The keys are generated with liboqs using the ML‑DSA‑65 algorithm.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_raw, secret_raw = sig.generate_keypair()
    public_pem = _pem_encode(public_raw, _PEM_PUBLIC_HEADER, _PEM_PUBLIC_FOOTER)
    private_pem = _pem_encode(secret_raw, _PEM_PRIVATE_HEADER, _PEM_PRIVATE_FOOTER)
    return public_pem, private_pem


def _payload(customer: str, product: str, expires: str, seats: int) -> bytes:
    """Canonical JSON payload (sorted keys) encoded as UTF‑8 bytes."""
    return json.dumps(
        {
            "customer": customer,
            "product": product,
            "expires": expires,
            "seats": seats,
        },
        sort_keys=True,
    ).encode()


def issue_license(
    private_key: bytes,
    customer: str,
    product: str,
    expires: str,
    seats: int = 1,
) -> str:
    """
    Create a license string signed with the vendor's private key.

    ``expires`` is an ISO‑date string, e.g. ``"2027-12-31"``.
    Returns the license string ready for distribution.
    """
    payload = _payload(customer, product, expires, seats)

    # Load the raw secret key from the PEM wrapper
    secret_raw = _pem_decode(
        private_key, _PEM_PRIVATE_HEADER, _PEM_PRIVATE_FOOTER
    )
    signer = oqs.Signature("ML-DSA-65", secret_key=secret_raw)

    signature = signer.sign(payload)

    # Assemble: 2‑byte length | payload | signature
    raw = struct.pack(">H", len(payload)) + payload + signature
    return PREFIX + base64.b32encode(raw).decode().rstrip("=")


def verify_license(
    public_key: bytes,
    license_key: str,
    product: str,
    today: datetime.date | None = None,
) -> dict | None:
    """
    Verify a license string.

    Returns the decoded license dict if the signature is valid, the product
    matches, and the expiry date has not passed; otherwise ``None``.
    """
    if not license_key.startswith(PREFIX):
        return None

    try:
        # Decode the base32 payload
        body = license_key[len(PREFIX) :]
        raw = base64.b32decode(body + "=" * (-len(body) % 8))

        # Extract length, payload and signature
        (n,) = struct.unpack(">H", raw[:2])
        payload, signature = raw[2 : 2 + n], raw[2 + n :]

        # Load the raw public key from PEM
        public_raw = _pem_decode(
            public_key, _PEM_PUBLIC_HEADER, _PEM_PUBLIC_FOOTER
        )
        verifier = oqs.Signature("ML-DSA-65")
        if not verifier.verify(payload, signature, public_raw):
            return None

        info = json.loads(payload)
    except (ValueError, struct.error, json.JSONDecodeError):
        return None

    today = today or datetime.date.today()
    if (
        info["product"] != product
        or datetime.date.fromisoformat(info["expires"]) < today
    ):
        return None
    return info
