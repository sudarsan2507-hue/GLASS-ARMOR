"""JWT‑style signed API tokens using the post‑quantum ML‑DSA‑65 signature.

The public API mirrors the classic ``jwt`` library used in the original
tests:

* ``jwt.encode(payload, key, algorithm=..., ttl_seconds=...)`` → token
* ``jwt.decode(token, key, algorithms=...)`` → payload (or raises ``InvalidToken``)

Internally the token format is the same as a classic JWT:

    token = base64url(header) "." base64url(claims) "." base64url(signature)

The signature covers the string ``"header.claims"`` and is bound to a fixed
context string (``"jwt"``) using liboqs’ *context‑aware* signing APIs.  This
prevents cross‑protocol replay attacks where a valid signature could be
re‑used on a different message type.

The original public functions ``generate_keypair``, ``issue_token`` and
``verify_token`` are retained for backward compatibility, and thin wrappers
``encode`` / ``decode`` are provided so the existing test‑suite (which expects
the classic ``jwt`` API) continues to work.
"""

import base64
import json
import time
from typing import Any, Dict, Iterable, Optional, Tuple

import oqs
from cryptography.exceptions import InvalidSignature  # kept for compatibility

# --------------------------------------------------------------------------- #
# Constants & helpers
# --------------------------------------------------------------------------- #

ALG = "ML-DSA-65"
# Fixed domain‑separation context for all JWT operations.
_CONTEXT = "jwt"


def _b64e(data: bytes) -> str:
    """Base64‑url encode without padding, returning a string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Base64‑url decode a string that may be missing padding."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- #
# Public key handling
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Token issuance
# --------------------------------------------------------------------------- #

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
    now = int(time.time() if now is None else now)
    body = dict(claims, iat=now, exp=now + ttl_seconds)

    # Header and payload are JSON‑encoded, then base64url‑encoded.
    header_b64 = _b64e(json.dumps({"alg": ALG, "typ": "JWT"}).encode())
    claims_b64 = _b64e(json.dumps(body, sort_keys=True).encode())
    signing_input = f"{header_b64}.{claims_b64}".encode()

    # Sign with liboqs, binding the fixed JWT context.
    signer = oqs.Signature(ALG, secret_key=private_key)
    # ``sign_with_ctx_str`` expects the message as bytes and the context as a
    # string; it returns the raw signature bytes.
    signature = signer.sign_with_ctx_str(signing_input, _CONTEXT)

    token = f"{header_b64}.{claims_b64}.{_b64e(signature)}"
    return token


# --------------------------------------------------------------------------- #
# Token verification
# --------------------------------------------------------------------------- #

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
    try:
        header_b64, claims_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(header_b64))
        claims = json.loads(_b64d(claims_b64))
        signature = _b64d(sig_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise InvalidToken("malformed token") from exc

    if header.get("alg") != ALG:
        raise InvalidToken("unexpected algorithm")

    verifier = oqs.Signature(ALG)
    signing_input = f"{header_b64}.{claims_b64}".encode()

    try:
        # Verify using the same context that was used during signing.
        ok = verifier.verify_with_ctx_str(signing_input, signature, _CONTEXT, public_key)
    except Exception as exc:  # liboqs may raise on malformed inputs
        raise InvalidToken("bad signature") from exc

    if not ok:
        raise InvalidToken("bad signature")

    # Expiration check.
    current = time.time() if now is None else now
    if claims.get("exp", 0) < current:
        raise InvalidToken("expired")

    return claims


# --------------------------------------------------------------------------- #
# Compatibility wrappers (classic ``jwt`` API)
# --------------------------------------------------------------------------- #

def encode(
    payload: Dict[str, Any],
    key: bytes,
    algorithm: str = ALG,
    ttl_seconds: int = 3600,
    **_: Any,
) -> str:
    """
    Compatibility wrapper that mimics ``jwt.encode``.

    Only the ``ML-DSA-65`` algorithm is supported; any other value results in
    ``InvalidToken`` to keep the behaviour consistent with the original tests.
    """
    if algorithm != ALG:
        raise InvalidToken(f"unsupported algorithm {algorithm!r}")
    return issue_token(private_key=key, claims=payload, ttl_seconds=ttl_seconds)


def decode(
    token: str,
    key: bytes,
    algorithms: Optional[Iterable[str]] = None,
    **_: Any,
) -> Dict[str, Any]:
    """
    Compatibility wrapper that mimics ``jwt.decode``.

    Parameters
    ----------
    token : str
        The JWT token.
    key : bytes
        The public key for verification.
    algorithms : iterable of str, optional
        Accepted algorithms.  If omitted, only ``ML-DSA-65`` is accepted.

    Returns
    -------
    dict
        The token claims.

    Raises
    ------
    InvalidToken
        If verification fails or the algorithm is not accepted.
    """
    if algorithms is not None:
        allowed = set(algorithms)
        if ALG not in allowed:
            raise InvalidToken("algorithm not allowed")
    # ``verify_token`` already raises ``InvalidToken`` for all failure modes.
    return verify_token(public_key=key, token=token)


# --------------------------------------------------------------------------- #
# Exported names
# --------------------------------------------------------------------------- #

__all__ = [
    "generate_keypair",
    "issue_token",
    "verify_token",
    "encode",
    "decode",
    "InvalidToken",
]
