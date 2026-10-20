"""Signed webhooks (ML‑DSA‑65), Stripe‑style signature header.

The sender signs "<timestamp>.<body>" and sends the header
    X-Signature: t=<unix time>,v1=<base64 signature>
The receiver keeps one public key per signature scheme (dict scheme -> key), checks the
signature for its scheme and rejects messages older than `tolerance` seconds (replay window).

The implementation uses post‑quantum signatures from liboqs (ML‑DSA‑65) while preserving
the original public API (`generate_keypair`, `sign_webhook`, `verify_webhook`).
PEM‑like wrappers are used so that the returned keys remain opaque ``bytes`` objects,
compatible with the original documentation.
"""

import base64
import time
from typing import Dict, Tuple

import oqs
from cryptography.exceptions import InvalidSignature  # kept for API compatibility


SCHEME = "v1"
_OQS_ALG = "ML-DSA-65"


# --------------------------------------------------------------------------- #
# PEM helpers – we store raw OQS keys inside a PEM‑style wrapper so that the
# public API still returns ``bytes`` that look like PEM data.
# --------------------------------------------------------------------------- #
def _bytes_to_pem(data: bytes, kind: str) -> bytes:
    """
    Encode raw key bytes into a PEM‑style block.

    ``kind`` is a short identifier, e.g. ``"ML-DSA PUBLIC"`` or ``"ML-DSA PRIVATE"``.
    """
    header = f"-----BEGIN {kind} KEY-----\n".encode()
    footer = f"-----END {kind} KEY-----\n".encode()
    b64 = base64.encodebytes(data)  # adds newline every 76 chars
    return header + b64 + footer


def _pem_to_bytes(pem: bytes, kind: str) -> bytes:
    """
    Decode a PEM‑style block produced by ``_bytes_to_pem``.
    """
    header = f"-----BEGIN {kind} KEY-----".encode()
    footer = f"-----END {kind} KEY-----".encode()
    if not (pem.startswith(header) and pem.rstrip().endswith(footer)):
        raise ValueError("Invalid PEM format for requested key kind")
    # Strip header/footer and any surrounding whitespace/newlines
    b64_body = pem.split(b"\n", 1)[1]
    b64_body = b64_body.rsplit(b"\n", 1)[0]
    return base64.decodebytes(b64_body)


# --------------------------------------------------------------------------- #
# Public API – unchanged signatures
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Return ``(public_key, private_key)`` as PEM‑style bytes for the webhook sender.
    The PEM blocks contain raw ML‑DSA‑65 key material.
    """
    sig = oqs.Signature(_OQS_ALG)
    public_key = sig.generate_keypair()          # raw bytes
    private_key = sig.export_secret_key()        # raw bytes
    public_pem = _bytes_to_pem(public_key, "ML-DSA PUBLIC")
    private_pem = _bytes_to_pem(private_key, "ML-DSA PRIVATE")
    return public_pem, private_pem


def sign_webhook(private_key: bytes, body: bytes, timestamp: int | None = None) -> str:
    """
    Return the ``X‑Signature`` header value for ``body`` (bytes).

    ``private_key`` must be the PEM block produced by :func:`generate_keypair`.
    """
    ts = int(time.time() if timestamp is None else timestamp)
    # Extract raw secret key from PEM wrapper
    sk = _pem_to_bytes(private_key, "ML-DSA PRIVATE")
    # liboqs expects the message as bytes
    message = str(ts).encode() + b"." + body
    signer = oqs.Signature(_OQS_ALG, secret_key=sk)
    signature = signer.sign(message)  # raw signature bytes
    b64_sig = base64.b64encode(signature).decode()
    return f"t={ts},{SCHEME}={b64_sig}"


def _parse(header: str) -> Dict[str, str]:
    """Parse a Stripe‑style header into a dict of fields."""
    fields: Dict[str, str] = {}
    for part in header.split(","):
        name, _, value = part.partition("=")
        fields[name.strip()] = value.strip()
    return fields


def verify_webhook(
    keys: Dict[str, bytes],
    body: bytes,
    header: str,
    now: float | None = None,
    tolerance: int = 300,
) -> bool:
    """
    ``keys``: mapping ``{scheme: public_key}`` where the public key is the PEM block
    returned by :func:`generate_keypair`. Returns ``True`` if the header is a fresh,
    valid signature of ``body``.
    """
    try:
        fields = _parse(header)
        ts = int(fields["t"])
        signature = base64.b64decode(fields[SCHEME])
        public_pem = keys[SCHEME]
        pk = _pem_to_bytes(public_pem, "ML-DSA PUBLIC")
        message = str(ts).encode() + b"." + body
        verifier = oqs.Signature(_OQS_ALG)
        ok = verifier.verify(message, signature, pk)
        if not ok:
            raise InvalidSignature  # unify error handling
    except (KeyError, ValueError, InvalidSignature, Exception):
        return False

    now = time.time() if now is None else now
    return abs(now - ts) <= tolerance
