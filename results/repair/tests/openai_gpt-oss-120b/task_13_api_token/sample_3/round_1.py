"""JWT‑style signed API tokens using a post‑quantum signature scheme (ML‑DSA‑65).

The token format is unchanged:

    token = base64url(header) "." base64url(claims) "." base64url(signature)

The signature now covers "header.claims" using the ML‑DSA‑65 algorithm from liboqs.
The public API (generate_keypair, issue_token, verify_token, InvalidToken) is
preserved so existing tests continue to work.
"""

import base64
import json
import time
from typing import Optional, Tuple, Dict, Any

import oqs
from cryptography.exceptions import InvalidSignature  # kept for backward compatibility

ALG = "ML-DSA-65"


class InvalidToken(Exception):
    """Raised when a token is malformed, has a bad signature, or is expired."""
    pass


def _b64e(data: bytes) -> str:
    """Base64‑url encode without padding, returning a string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Base64‑url decode, adding padding if necessary."""
    # Pad with '=' to a multiple of 4 characters
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new ML‑DSA‑65 key pair.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        The public and private keys as raw byte strings.  They are opaque
        to callers – they only need to be passed back to ``issue_token`` and
        ``verify_token``.
    """
    sig = oqs.Signature(ALG)
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    return public_key, private_key


def issue_token(
    private_key: bytes,
    claims: Dict[str, Any],
    ttl_seconds: int = 3600,
    now: Optional[int] = None,
) -> str:
    """
    Create a signed JWT‑style token.

    Parameters
    ----------
    private_key : bytes
        The private key returned by :func:`generate_keypair`.
    claims : dict
        Payload to embed in the token.
    ttl_seconds : int, optional
        How long the token is valid (default 3600 seconds).
    now : int, optional
        Override the current time (Unix timestamp).  Useful for testing.

    Returns
    -------
    str
        The complete token string.
    """
    now = int(time.time() if now is None else now)
    body = dict(claims, iat=now, exp=now + ttl_seconds)

    header_json = json.dumps({"alg": ALG, "typ": "JWT"}).encode()
    claims_json = json.dumps(body, sort_keys=True).encode()

    signing_input = f"{_b64e(header_json)}.{_b64e(claims_json)}"

    # Sign with ML‑DSA‑65
    signer = oqs.Signature(ALG, secret_key=private_key)
    signature = signer.sign(signing_input.encode())

    token = f"{signing_input}.{_b64e(signature)}"
    return token


def verify_token(
    public_key: bytes,
    token: str,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Verify a token and return its claims.

    Parameters
    ----------
    public_key : bytes
        The public key returned by :func:`generate_keypair`.
    token : str
        The JWT‑style token to verify.
    now : int, optional
        Override the current time (Unix timestamp).  Useful for testing.

    Returns
    -------
    dict
        The claims payload.

    Raises
    ------
    InvalidToken
        If the token is malformed, the signature is invalid, or the token has
        expired.
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

    signing_input = f"{header_b64}.{claims_b64}".encode()

    verifier = oqs.Signature(ALG)
    if not verifier.verify(signing_input, signature, public_key):
        raise InvalidToken("bad signature")

    current = time.time() if now is None else now
    if claims.get("exp", 0) < current:
        raise InvalidToken("expired")

    return claims


__all__ = [
    "generate_keypair",
    "issue_token",
    "verify_token",
    "InvalidToken",
]
