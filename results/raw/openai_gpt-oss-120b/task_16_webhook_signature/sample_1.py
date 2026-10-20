"""Signed webhooks (ML‑DSA‑65), Stripe‑style signature header.

The sender signs "<timestamp>.<body>" and sends the header
    X-Signature: t=<unix time>,v1=<base64 signature>
The receiver keeps one public key per signature scheme (dict scheme -> key), checks the
signature for its scheme and rejects messages older than `tolerance` seconds (replay window).

This module mirrors the original ECDSA implementation but uses post‑quantum
ML‑DSA‑65 via liboqs.  Keys are still exchanged as PEM‑encoded bytes so existing
tests that expect PEM format continue to work.
"""
import base64
import time
from typing import Tuple, Dict

import oqs
from cryptography.exceptions import InvalidSignature  # kept for API compatibility

SCHEME = "v1"
_OQS_ALG = "ML-DSA-65"


# --------------------------------------------------------------------------- #
# PEM helpers – liboqs works with raw bytes, but we expose PEM strings to keep
# the public API unchanged.
# --------------------------------------------------------------------------- #
def _pem_wrap(data: bytes, label: str) -> bytes:
    """Wrap raw bytes in a PEM block with the given label."""
    b64 = base64.encodebytes(data).replace(b"\n", b"")
    lines = [b"-----BEGIN " + label.encode() + b"-----"]
    # split into 64‑byte chunks as typical PEM format
    for i in range(0, len(b64), 64):
        lines.append(b64[i : i + 64])
    lines.append(b"-----END " + label.encode() + b"-----")
    lines.append(b"")
    return b"\n".join(lines)


def _pem_unwrap(pem: bytes, label: str) -> bytes:
    """Extract raw bytes from a PEM block with the given label."""
    header = b"-----BEGIN " + label.encode() + b"-----"
    footer = b"-----END " + label.encode() + b"-----"
    if not (pem.startswith(header) and footer in pem):
        raise ValueError("Invalid PEM format for " + label)
    # strip header/footer and any whitespace/newlines
    body = pem.split(header, 1)[1].split(footer, 1)[0]
    body = b"".join(body.split())
    return base64.b64decode(body)


# --------------------------------------------------------------------------- #
# Public API – generate_keypair, sign_webhook, verify_webhook
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """Return (public_key, private_key) as PEM‑encoded bytes for the webhook sender."""
    sig = oqs.Signature(_OQS_ALG)
    public_raw, secret_raw = sig.generate_keypair()
    public_pem = _pem_wrap(public_raw, "PUBLIC KEY")
    private_pem = _pem_wrap(secret_raw, "PRIVATE KEY")
    return public_pem, private_pem


def sign_webhook(private_key: bytes, body: bytes, timestamp: int | None = None) -> str:
    """Return the X‑Signature header value for `body` (bytes)."""
    ts = int(time.time() if timestamp is None else timestamp)
    # Decode the PEM‑encoded private key to raw bytes
    secret_raw = _pem_unwrap(private_key, "PRIVATE KEY")
    # Initialise the OQS signer with the secret key
    signer = oqs.Signature(_OQS_ALG, secret_key=secret_raw)
    message = str(ts).encode() + b"." + body
    signature = signer.sign(message)  # returns raw bytes
    b64_sig = base64.b64encode(signature).decode()
    return f"t={ts},{SCHEME}={b64_sig}"


def _parse(header: str) -> Dict[str, str]:
    """Parse a Stripe‑style signature header into a dict."""
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
    Verify a webhook signature.

    * ``keys`` – mapping ``scheme -> public_key`` where the public key is PEM‑encoded.
    * ``body`` – raw request body.
    * ``header`` – the value of the ``X‑Signature`` header.
    * ``now`` – optional current time (for testing).
    * ``tolerance`` – allowed replay window in seconds.

    Returns ``True`` iff the signature is valid and the timestamp is within the
    replay window.
    """
    try:
        fields = _parse(header)
        ts = int(fields["t"])
        b64_sig = fields[SCHEME]
        signature = base64.b64decode(b64_sig)

        # Load the PEM‑encoded public key for the expected scheme
        public_pem = keys[SCHEME]
        public_raw = _pem_unwrap(public_pem, "PUBLIC KEY")

        verifier = oqs.Signature(_OQS_ALG)
        message = str(ts).encode() + b"." + body
        ok = verifier.verify(message, signature, public_raw)
        if not ok:
            raise InvalidSignature  # unify error handling with the old API
    except (KeyError, ValueError, InvalidSignature):
        return False

    now = time.time() if now is None else now
    return abs(now - ts) <= tolerance
