"""JWT‑style signed API tokens using a post‑quantum signature scheme (ML‑DSA‑65).

The token format is unchanged:

    token = base64url(header) "." base64url(claims) "." base64url(signature)

The signature now covers ``header.claims`` using the ML‑DSA‑65 algorithm from
liboqs.  The public API (``generate_keypair``, ``issue_token``, ``verify_token``,
``InvalidToken``) is identical to the original RSA‑based implementation so
existing tests continue to work.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Tuple, Dict, Any

import oqs

ALG = "ML-DSA-65"


class InvalidToken(Exception):
    """Raised when a token is malformed, has a bad signature, or is expired."""
    pass


def _b64e(data: bytes) -> str:
    """Base64‑url encode *without* padding and return a string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Base64‑url decode a string that may be missing padding."""
    # Pad with ``=`` to a multiple of 4 characters.
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded)


# --------------------------------------------------------------------------- #
# Key handling (ML‑DSA‑65)
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new ML‑DSA‑65 key pair.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        * ``public_key`` – raw public‑key bytes.
        * ``private_key`` – raw secret‑key bytes.
    """
    # ``oqs.Signature`` implements ``__enter__``/``__exit__`` so we can use a
    # context manager to ensure native resources are released promptly.
    with oqs.Signature(ALG) as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Token issuance
# --------------------------------------------------------------------------- #
def issue_token(
    private_key: bytes,
    claims: Dict[str, Any],
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
        Payload to embed in the token.
    ttl_seconds : int, optional
        How long the token is valid (default 3600 seconds).
    now : int, optional
        Override the current time (Unix timestamp) – useful for testing.

    Returns
    -------
    str
        The complete token string ``header.claims.signature``.
    """
    now_ts = int(time.time() if now is None else now)
    body = dict(claims, iat=now_ts, exp=now_ts + ttl_seconds)

    header_json = json.dumps({"alg": ALG, "typ": "JWT"}).encode()
    claims_json = json.dumps(body, sort_keys=True).encode()

    signing_input = f"{_b64e(header_json)}.{_b64e(claims_json)}"

    # Sign with ML‑DSA‑65
    with oqs.Signature(ALG, secret_key=private_key) as signer:
        signature = signer.sign(signing_input.encode())

    return f"{signing_input}.{_b64e(signature)}"


# --------------------------------------------------------------------------- #
# Token verification
# --------------------------------------------------------------------------- #
def verify_token(
    public_key: bytes,
    token: str,
    now: int | None = None,
) -> Dict[str, Any]:
    """
    Verify a token and return its claims.

    Parameters
    ----------
    public_key : bytes
        The public key returned by :func:`generate_keypair`.
    token : str
        The token string to verify.
    now : int, optional
        Override the current time (Unix timestamp) – useful for testing.

    Returns
    -------
    dict
        The decoded claims.

    Raises
    ------
    InvalidToken
        If the token is malformed, has an unexpected algorithm, a bad
        signature, or is expired.
    """
    try:
        header_b64, claims_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(header_b64))
        claims = json.loads(_b64d(claims_b64))
        signature = _b64d(sig_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise InvalidToken("malformed token") from exc

    if header.get("alg") != ALG:
        raise InvalidToken("unexpected algorithm")

    signing_input = f"{header_b64}.{claims_b64}"

    # Verify with ML‑DSA‑65
    with oqs.Signature(ALG) as verifier:
        try:
            ok = verifier.verify(signing_input.encode(), signature, public_key)
        except Exception as exc:  # liboqs may raise generic exceptions on failure
            raise InvalidToken(f"verification error: {exc}") from exc

    if not ok:
        raise InvalidToken("bad signature")

    current = time.time() if now is None else now
    if claims.get("exp", 0) < current:
        raise InvalidToken("expired")

    return claims
