"""JWT‑style signed API tokens (ML‑DSA‑65 post‑quantum signature).

The token format follows the classic JWT layout:

    token = base64url(header) "." base64url(claims) "." base64url(signature)

The signature covers the string "header.claims".  The verifier only accepts the
expected algorithm and rejects expired tokens.

The implementation has been migrated from RSA‑PKCS#1 v1.5 (RS256) to the
post‑quantum signature scheme **ML‑DSA‑65** provided by the *liboqs* Python
bindings.  The public API (`generate_keypair`, `issue_token`,
`verify_token`, `InvalidToken`) is unchanged, so existing tests continue to
work.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Tuple

import oqs
from cryptography.exceptions import InvalidSignature  # retained for compatibility

ALG = "ML-DSA-65"


class InvalidToken(Exception):
    """Raised when a token is malformed, has a bad signature, or is expired."""
    pass


def _b64e(data: bytes) -> str:
    """Base64‑url encode without padding, returning a string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Base64‑url decode a string that may be missing padding."""
    # Add the minimal padding required for a valid base64 string.
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new ML‑DSA‑65 key pair.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        The public and private keys as raw byte strings.  They can be stored
        directly or transmitted; they are not PEM‑encoded because the
        liboqs API works with raw bytes.
    """
    sig = oqs.Signature(ALG)
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    return public_key, private_key


def issue_token(
    private_key: bytes,
    claims: dict,
    ttl_seconds: int = 3600,
    now: int | None = None,
) -> str:
    """
    Create a signed JWT‑style token.

    Parameters
    ----------
    private_key : bytes
        The secret key returned by :func:`generate_keypair`.
    claims : dict
        Arbitrary claim data that will be JSON‑encoded.
    ttl_seconds : int, optional
        Time‑to‑live for the token (default 3600 seconds).
    now : int, optional
        Override the current Unix time (useful for testing).

    Returns
    -------
    str
        The complete token string ``header.claims.signature``.
    """
    now_int = int(time.time() if now is None else now)
    body = dict(claims, iat=now_int, exp=now_int + ttl_seconds)

    # Header and payload are JSON‑encoded, then base64url‑encoded.
    header_b64 = _b64e(json.dumps({"alg": ALG, "typ": "JWT"}).encode())
    claims_b64 = _b64e(json.dumps(body, sort_keys=True).encode())
    signing_input = f"{header_b64}.{claims_b64}".encode()

    # Sign with liboqs.
    signer = oqs.Signature(ALG, secret_key=private_key)
    signature = signer.sign(signing_input)

    token = f"{header_b64}.{claims_b64}.{_b64e(signature)}"
    return token


def verify_token(
    public_key: bytes,
    token: str,
    now: int | None = None,
) -> dict:
    """
    Verify a token and return its claims.

    Parameters
    ----------
    public_key : bytes
        The public key returned by :func:`generate_keypair`.
    token : str
        The JWT‑style token string.
    now : int, optional
        Override the current Unix time (useful for testing).

    Returns
    -------
    dict
        The decoded claims.

    Raises
    ------
    InvalidToken
        If the token is malformed, the algorithm does not match, the signature
        is invalid, or the token has expired.
    """
    # Split into exactly three parts; any deviation is malformed.
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidToken("malformed token")
    header_b64, claims_b64, sig_b64 = parts

    try:
        header = json.loads(_b64d(header_b64))
        claims = json.loads(_b64d(claims_b64))
        signature = _b64d(sig_b64)
    except (json.JSONDecodeError, base64.binascii.Error) as exc:
        raise InvalidToken("malformed token") from exc

    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise InvalidToken("malformed token")

    if header.get("alg") != ALG:
        raise InvalidToken("unexpected algorithm")

    verifier = oqs.Signature(ALG)
    signing_input = f"{header_b64}.{claims_b64}".encode()
    try:
        ok = verifier.verify(signing_input, signature, public_key)
    except Exception as exc:  # liboqs may raise on malformed inputs
        raise InvalidToken("bad signature") from exc

    if not ok:
        raise InvalidToken("bad signature")

    # Expiration check.
    current = time.time() if now is None else now
    if claims.get("exp", 0) < current:
        raise InvalidToken("expired")

    return claims
