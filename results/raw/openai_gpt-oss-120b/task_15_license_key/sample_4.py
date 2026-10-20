"""Offline software license keys (ML‑DSA‑65).

The vendor signs {customer, product, expires, seats}. The license string is
"LIC1-" + base32(2‑byte payload length | payload JSON | signature), so it can be
pasted into the app. The app checks the signature, the product name and the
expiry date.

This module used to rely on ECDSA‑P256.  It has been migrated to the
post‑quantum signature scheme ML‑DSA‑65 via liboqs while keeping the public
API (`generate_keypair`, `issue_license`, `verify_license`) unchanged.
"""
import base64
import datetime
import json
import struct
from typing import Tuple

import oqs

# --------------------------------------------------------------------------- #
# PEM helpers – liboqs does not provide PEM encoding, so we wrap the raw
# key bytes in a simple PEM‑like container.  This keeps the original API
# (returning PEM bytes) while remaining self‑contained.
# --------------------------------------------------------------------------- #

_PEM_LINE_LENGTH = 64
_PUBLIC_PEM_HEADER = b"-----BEGIN ML-DSA PUBLIC KEY-----"
_PUBLIC_PEM_FOOTER = b"-----END ML-DSA PUBLIC KEY-----"
_PRIVATE_PEM_HEADER = b"-----BEGIN ML-DSA PRIVATE KEY-----"
_PRIVATE_PEM_FOOTER = b"-----END ML-DSA PRIVATE KEY-----"


def _pem_wrap(key_bytes: bytes, header: bytes, footer: bytes) -> bytes:
    """Wrap raw key bytes in a PEM‑like container."""
    b64 = base64.b64encode(key_bytes).decode()
    lines = [b64[i : i + _PEM_LINE_LENGTH] for i in range(0, len(b64), _PEM_LINE_LENGTH)]
    pem = b"\n".join([header] + [line.encode() for line in lines] + [footer])
    return pem + b"\n"


def _pem_unwrap(pem_bytes: bytes, header: bytes, footer: bytes) -> bytes:
    """Extract raw key bytes from a PEM‑like container."""
    if not (pem_bytes.startswith(header) and pem_bytes.rstrip().endswith(footer)):
        raise ValueError("Invalid PEM format")
    # Strip header/footer and any surrounding whitespace/newlines
    body = pem_bytes[len(header) : -len(footer)]
    body = body.strip().replace(b"\n", b"")
    return base64.b64decode(body)


# --------------------------------------------------------------------------- #
# License handling (public API)
# --------------------------------------------------------------------------- #

PREFIX = "LIC1-"


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Return ``(public_key, private_key)`` as PEM‑encoded bytes for the vendor.
    The keys are generated with the post‑quantum scheme **ML‑DSA‑65**.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_raw = sig.generate_keypair()          # bytes
    private_raw = sig.export_secret_key()        # bytes

    public_pem = _pem_wrap(public_raw, _PUBLIC_PEM_HEADER, _PUBLIC_PEM_FOOTER)
    private_pem = _pem_wrap(private_raw, _PRIVATE_PEM_HEADER, _PRIVATE_PEM_FOOTER)
    return public_pem, private_pem


def _payload(customer: str, product: str, expires: str, seats: int) -> bytes:
    """Serialize the license payload – deterministic JSON, UTF‑8 encoded."""
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
    private_key: bytes, customer: str, product: str, expires: str, seats: int = 1
) -> str:
    """
    Create a license string signed with the vendor's private key.

    ``expires`` must be an ISO‑date string, e.g. ``"2027-12-31"``.
    Returns the license string ready for distribution.
    """
    payload = _payload(customer, product, expires, seats)

    # Load the raw private key from our PEM wrapper
    priv_raw = _pem_unwrap(private_key, _PRIVATE_PEM_HEADER, _PRIVATE_PEM_FOOTER)

    # Sign with ML‑DSA‑65
    signer = oqs.Signature("ML-DSA-65", secret_key=priv_raw)
    signature = signer.sign(payload)  # bytes

    # Assemble: 2‑byte length | payload | signature
    raw = struct.pack(">H", len(payload)) + payload + signature
    return PREFIX + base64.b32encode(raw).decode().rstrip("=")


def verify_license(
    public_key: bytes, license_key: str, product: str, today: datetime.date | None = None
) -> dict | None:
    """
    Verify a license string.

    Returns the decoded payload dict if the signature is valid, the product
    matches, and the license has not expired; otherwise ``None``.
    """
    if not license_key.startswith(PREFIX):
        return None

    try:
        # Decode the base32 payload (pad with "=" to a multiple of 8)
        body = license_key[len(PREFIX) :]
        raw = base64.b32decode(body + "=" * (-len(body) % 8))

        # Split length, payload and signature
        (payload_len,) = struct.unpack(">H", raw[:2])
        payload = raw[2 : 2 + payload_len]
        signature = raw[2 + payload_len :]

        # Load the raw public key from PEM
        pub_raw = _pem_unwrap(public_key, _PUBLIC_PEM_HEADER, _PUBLIC_PEM_FOOTER)

        # Verify with ML‑DSA‑65
        verifier = oqs.Signature("ML-DSA-65")
        if not verifier.verify(payload, signature, pub_raw):
            return None

        info = json.loads(payload)

    except (ValueError, struct.error, OSError, Exception):
        # OSError can be raised by liboqs on verification failure; we treat any
        # exception as a verification error.
        return None

    # Date checks
    today = today or datetime.date.today()
    if (
        info.get("product") != product
        or datetime.date.fromisoformat(info.get("expires", "1970-01-01")) < today
    ):
        return None

    return info
