"""JWT‑style signed API tokens using a post‑quantum signature scheme (ML‑DSA‑65).

The token format is unchanged:

    token = base64url(header) "." base64url(claims) "." base64url(signature)

The signature now covers ``header.claims`` using the ML‑DSA‑65 algorithm from
*liboqs*, with an explicit context to bind the signature to JWT usage.
The public API (``generate_keypair``, ``encode``/``decode`` (aliases for the
original ``issue_token``/``verify_token``), and ``InvalidToken``) matches the
original RSA‑based implementation so existing tests continue to work.
"""

import base64
import json
import time
from typing import Tuple, Dict, Any

import oqs
from cryptography.exceptions import InvalidSignature  # retained for compatibility

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
ALG = "ML-DSA-65"
# A constant context string that is included in every signature/verification.
# Using a context prevents the signature from being valid if the signed
# material is altered without also updating the context.
CTX = "jwt"


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class InvalidToken(Exception):
    """Raised when a token is malformed, has a bad signature, or is expired."""
    pass


# --------------------------------------------------------------------------- #
# Helper functions for base64url encoding/decoding
# --------------------------------------------------------------------------- #
def _b64e(data: bytes) -> str:
    """Base64‑url encode without padding and return a string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Base64‑url decode a string that may be missing padding."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- #
# Key handling (ML‑DSA‑65)
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new ML‑DSA‑65 key pair.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        * ``public_key`` – raw public key bytes.
        * ``private_key`` – raw secret key bytes.
    """
    sig = oqs.Signature(ALG)
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Token issuance (internal implementation)
# --------------------------------------------------------------------------- #
def _issue_token(
    private_key: bytes,
    claims: Dict[str, Any],
    ttl_seconds: int = 3600,
    now: int | None = None,
) -> str:
    """
    Core implementation that creates a signed JWT‑style token.

    This function is deliberately kept private; the public name ``encode``
    (compatible with the original library) forwards to it.
    """
    now_ts = int(time.time() if now is None else now)
    body = dict(claims, iat=now_ts, exp=now_ts + ttl_seconds)

    header_json = json.dumps({"alg": ALG, "typ": "JWT"}).encode()
    claims_json = json.dumps(body, sort_keys=True).encode()

    signing_input = f"{_b64e(header_json)}.{_b64e(claims_json)}"
    signing_input_bytes = signing_input.encode()  # liboqs expects bytes

    signer = oqs.Signature(ALG, secret_key=private_key)
    signature = signer.sign_with_ctx_str(signing_input_bytes, CTX)

    return f"{signing_input}.{_b64e(signature)}"


# --------------------------------------------------------------------------- #
# Token verification (internal implementation)
# --------------------------------------------------------------------------- #
def _verify_token(
    public_key: bytes,
    token: str,
    now: int | None = None,
) -> Dict[str, Any]:
    """
    Core implementation that verifies a token and returns its claims.

    The public name ``decode`` (compatible with the original library) forwards
    to this function.
    """
    try:
        header_b64, claims_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(header_b64))
        claims = json.loads(_b64d(claims_b64))
        signature = _b64d(sig_b64)
    except Exception as exc:  # includes ValueError, json.JSONDecodeError, etc.
        raise InvalidToken("malformed token") from exc

    if header.get("alg") != ALG:
        raise InvalidToken("unexpected algorithm")

    signing_input = f"{header_b64}.{claims_b64}"
    signing_input_bytes = signing_input.encode()

    verifier = oqs.Signature(ALG)
    try:
        ok = verifier.verify_with_ctx_str(signing_input_bytes, signature, CTX, public_key)
    except Exception as exc:  # liboqs may raise generic exceptions on failure
        raise InvalidToken(f"verification error: {exc}") from exc

    if not ok:
        raise InvalidToken("bad signature")

    current = time.time() if now is None else now
    if claims.get("exp", 0) < current:
        raise InvalidToken("expired")

    return claims


# --------------------------------------------------------------------------- #
# Public API – aliases matching the original RSA‑based implementation
# --------------------------------------------------------------------------- #
def encode(
    private_key: bytes,
    claims: Dict[str, Any],
    ttl_seconds: int = 3600,
    now: int | None = None,
) -> str:
    """
    Issue a JWT‑style token.

    This is a thin wrapper around the internal ``_issue_token`` function and
    exists for backward compatibility with the original API.
    """
    return _issue_token(private_key, claims, ttl_seconds, now)


def decode(
    public_key: bytes,
    token: str,
    now: int | None = None,
) -> Dict[str, Any]:
    """
    Verify a JWT‑style token and return its claims.

    This is a thin wrapper around the internal ``_verify_token`` function and
    exists for backward compatibility with the original API.
    """
    return _verify_token(public_key, token, now)


# --------------------------------------------------------------------------- #
# Backward‑compatible names (the original code used these)
# --------------------------------------------------------------------------- #
# The original implementation exposed ``issue_token`` and ``verify_token``.
# They are kept as aliases so that either naming style works.
issue_token = encode
verify_token = decode

__all__ = [
    "generate_keypair",
    "encode",
    "decode",
    "issue_token",
    "verify_token",
    "InvalidToken",
]
