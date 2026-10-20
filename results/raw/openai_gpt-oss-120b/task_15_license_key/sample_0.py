"""Offline software license keys (ML‑DSA‑65).

The vendor signs {customer, product, expires, seats}. The license string is
"LIC1-" + base32(2‑byte payload length | payload JSON | signature), so it can be
pasted into the app. The app checks the signature, the product name and the
expiry date.

The implementation has been migrated from classical ECDSA (P‑256) to the
post‑quantum signature scheme **ML‑DSA‑65** using the *liboqs* Python bindings.
The public API (function names and return types) is unchanged, so existing
tests continue to work.
"""
import base64
import datetime
import json
import struct
import textwrap

import oqs
from cryptography.exceptions import InvalidSignature

# --------------------------------------------------------------------------- #
# PEM handling for liboqs keys (they are raw bytes, we wrap them in a PEM‑like
# format so the rest of the code can keep using PEM bytes).
# --------------------------------------------------------------------------- #

_PEM_PUBLIC_HEADER = b"-----BEGIN ML-DSA PUBLIC KEY-----"
_PEM_PUBLIC_FOOTER = b"-----END ML-DSA PUBLIC KEY-----"
_PEM_PRIVATE_HEADER = b"-----BEGIN ML-DSA PRIVATE KEY-----"
_PEM_PRIVATE_FOOTER = b"-----END ML-DSA PRIVATE KEY-----"


def _pem_wrap(raw: bytes, header: bytes, footer: bytes) -> bytes:
    """Wrap raw bytes in a PEM‑like block."""
    b64 = base64.b64encode(raw)
    # split into 64‑character lines like typical PEM files
    lines = textwrap.wrap(b64.decode(), 64)
    pem = b"\n".join([header] + [line.encode() for line in lines] + [footer, b""])
    return pem


def _pem_unwrap(pem: bytes, header: bytes, footer: bytes) -> bytes:
    """Extract raw bytes from a PEM‑like block; raises ValueError on format errors."""
    if not (pem.startswith(header) and pem.rstrip().endswith(footer)):
        raise ValueError("Invalid PEM format")
    # Strip header/footer and any surrounding whitespace / newlines
    body = pem[len(header) : -len(footer)]
    body = body.strip().replace(b"\n", b"")
    return base64.b64decode(body)


def _public_key_to_pem(pub: bytes) -> bytes:
    return _pem_wrap(pub, _PEM_PUBLIC_HEADER, _PEM_PUBLIC_FOOTER)


def _private_key_to_pem(priv: bytes) -> bytes:
    return _pem_wrap(priv, _PEM_PRIVATE_HEADER, _PEM_PRIVATE_FOOTER)


def _pem_to_public_key(pem: bytes) -> bytes:
    return _pem_unwrap(pem, _PEM_PUBLIC_HEADER, _PEM_PUBLIC_FOOTER)


def _pem_to_private_key(pem: bytes) -> bytes:
    return _pem_unwrap(pem, _PEM_PRIVATE_HEADER, _PEM_PRIVATE_FOOTER)


# --------------------------------------------------------------------------- #
# License handling (public API)
# --------------------------------------------------------------------------- #

PREFIX = "LIC1-"
_KEM_ALG = "ML-DSA-65"          # signature algorithm used throughout


def generate_keypair():
    """Return (public_key, private_key) as PEM‑encoded bytes for the vendor."""
    sig = oqs.Signature(_KEM_ALG)
    public_key = sig.generate_keypair()          # raw bytes
    private_key = sig.export_secret_key()        # raw bytes
    return _public_key_to_pem(public_key), _private_key_to_pem(private_key)


def _payload(customer, product, expires, seats):
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


def issue_license(private_key, customer, product, expires, seats=1):
    """Create a license string signed with the vendor's private key.

    * ``private_key`` – PEM‑encoded ML‑DSA private key (bytes)
    * ``expires`` – ISO date string, e.g. ``"2027-12-31"``
    * Returns the license string ready to be handed to a client.
    """
    payload = _payload(customer, product, expires, seats)

    # Load the raw private key bytes from the PEM wrapper
    raw_priv = _pem_to_private_key(private_key)

    # Sign using liboqs
    signer = oqs.Signature(_KEM_ALG, secret_key=raw_priv)
    signature = signer.sign(payload)

    # Assemble: 2‑byte length | payload | signature
    raw = struct.pack(">H", len(payload)) + payload + signature
    return PREFIX + base64.b32encode(raw).decode().rstrip("=")


def verify_license(public_key, license_key, product, today=None):
    """Validate a license string.

    Returns the decoded payload dict if the signature is valid, the product
    matches and the license has not expired; otherwise ``None``.
    """
    if not license_key.startswith(PREFIX):
        return None

    try:
        # Decode the base32 body (pad with "=" to a multiple of 8)
        body = license_key[len(PREFIX) :]
        raw = base64.b32decode(body + "=" * (-len(body) % 8))

        # Split length, payload and signature
        (n,) = struct.unpack(">H", raw[:2])
        payload, signature = raw[2 : 2 + n], raw[2 + n :]

        # Load the raw public key bytes from the PEM wrapper
        raw_pub = _pem_to_public_key(public_key)

        # Verify using liboqs
        verifier = oqs.Signature(_KEM_ALG)
        if not verifier.verify(payload, signature, raw_pub):
            raise InvalidSignature  # unify error handling

        info = json.loads(payload)

    except (ValueError, struct.error, InvalidSignature, oqs.OQSError):
        # Any parsing, decoding or verification problem results in an invalid license
        return None

    # Date checks
    today = today or datetime.date.today()
    if (
        info["product"] != product
        or datetime.date.fromisoformat(info["expires"]) < today
    ):
        return None

    return info
