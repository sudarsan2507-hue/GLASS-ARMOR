"""Signed webhooks (ML‑DSA‑65), Stripe‑style signature header.

The sender signs "<timestamp>.<body>" and sends the header
    X-Signature: t=<unix time>,v1=<base64 signature>
The receiver keeps one public key per signature scheme (dict scheme -> key), checks the
signature for its scheme and rejects messages older than `tolerance` seconds (replay window).

This module mirrors the original ECDSA implementation but uses the post‑quantum
ML‑DSA‑65 algorithm from liboqs.  Public functions retain the same signatures so
existing tests continue to pass.
"""

import base64
import time
from typing import Tuple, Dict

import oqs
from cryptography.exceptions import InvalidSignature

SCHEME = "v1"
_OQS_ALG = "ML-DSA-65"


# --------------------------------------------------------------------------- #
# PEM helpers – liboqs works with raw bytes, but the original API used PEM.
# --------------------------------------------------------------------------- #
def _bytes_to_pem(data: bytes, label: str) -> bytes:
    """Wrap raw bytes in a PEM block with the given label."""
    b64 = base64.b64encode(data).decode()
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    pem = (
        f"-----BEGIN {label}-----\n"
        + "\n".join(lines)
        + f"\n-----END {label}-----\n"
    )
    return pem.encode()


def _pem_to_bytes(pem: bytes, label: str) -> bytes:
    """Extract raw bytes from a PEM block with the given label."""
    header = f"-----BEGIN {label}-----".encode()
    footer = f"-----END {label}-----".encode()
    if not (pem.startswith(header) and pem.rstrip().endswith(footer)):
        raise ValueError("Invalid PEM format")
    # Strip header/footer and newlines
    body = pem.replace(header, b"").replace(footer, b"")
    body = b"".join(body.split())
    return base64.b64decode(body)


# --------------------------------------------------------------------------- #
# Public API – generate_keypair, sign_webhook, verify_webhook
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Return ``(public_key, private_key)`` as PEM‑encoded bytes for the webhook sender.

    The keys are generated with ML‑DSA‑65.  The PEM labels are ``PUBLIC KEY`` and
    ``PRIVATE KEY`` to stay compatible with the original interface.
    """
    sig = oqs.Signature(_OQS_ALG)
    public_raw = sig.generate_keypair()          # bytes
    private_raw = sig.export_secret_key()        # bytes
    public_pem = _bytes_to_pem(public_raw, "PUBLIC KEY")
    private_pem = _bytes_to_pem(private_raw, "PRIVATE KEY")
    return public_pem, private_pem


def sign_webhook(private_key: bytes, body: bytes, timestamp: int | None = None) -> str:
    """
    Return the ``X‑Signature`` header value for ``body`` (bytes).

    ``private_key`` must be the PEM‑encoded private key produced by
    :func:`generate_keypair`.  The timestamp is optional; if omitted the current
    Unix time is used.
    """
    ts = int(time.time() if timestamp is None else timestamp)
    # Decode PEM to raw secret key bytes
    private_raw = _pem_to_bytes(private_key, "PRIVATE KEY")
    sig = oqs.Signature(_OQS_ALG, secret_key=private_raw)
    message = str(ts).encode() + b"." + body
    signature = sig.sign(message)                # bytes
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

    ``keys`` is a mapping ``{scheme: public_key}`` where the public key is the
    PEM‑encoded public key produced by :func:`generate_keypair`.  The function
    returns ``True`` iff the header contains a fresh, valid signature of ``body``.
    """
    try:
        fields = _parse(header)
        ts = int(fields["t"])
        b64_sig = fields[SCHEME]
        signature = base64.b64decode(b64_sig)

        # Load the PEM‑encoded public key for the expected scheme
        public_pem = keys[SCHEME]
        public_raw = _pem_to_bytes(public_pem, "PUBLIC KEY")

        verifier = oqs.Signature(_OQS_ALG)
        message = str(ts).encode() + b"." + body
        if not verifier.verify(message, signature, public_raw):
            raise InvalidSignature  # unify error handling
    except (KeyError, ValueError, InvalidSignature, oqs.OQSError):
        return False

    now = time.time() if now is None else now
    return abs(now - ts) <= tolerance
