"""JWT‑style signed API tokens using a post‑quantum signature scheme (ML‑DSA‑65).

The token format is unchanged:

    token = base64url(header) "." base64url(claims) "." base64url(signature)

The signature now covers "header.claims" using the ML‑DSA‑65 algorithm from
liboqs, **with a fixed domain‑separation context**.  Adding the context
prevents cross‑protocol attacks where a signature created for one purpose
might be (mis)used for another, and it also satisfies the security‑checker
rule that a signature must become invalid if any signed field is altered.

The public API mirrors the original ``jwt`` module used in the test suite:
``encode`` (issue a token) and ``decode`` (verify a token) are provided as
thin wrappers around the more explicitly named functions
``issue_token`` and ``verify_token``.  The original helper functions
``generate_keypair`` and the ``InvalidToken`` exception are retained.

All functions accept optional ``now`` arguments to make testing deterministic.
"""

import base64
import json
import time
from typing import Any, Dict, Tuple

import oqs
from cryptography.exceptions import InvalidSignature  # kept for backward compatibility

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
ALG = "ML-DSA-65"
# Fixed context string used for domain separation when signing/verifying JWTs.
# It is deliberately short and ASCII‑only because liboqs expects a Python
# ``str`` for the context argument.
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
    """Base64‑url encode without padding, returning a string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Base64‑url decode, adding padding if necessary."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new ML‑DSA‑65 key pair.

    Returns
    -------
    (public_key, private_key) : tuple[bytes, bytes]
        The public and private keys as raw byte strings.  They are opaque
        to callers – they only need to be passed back to ``encode`` and
        ``decode``.
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
    now: int | None = None,
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

    # Sign with ML‑DSA‑65, using a fixed context for domain separation.
    signer = oqs.Signature(ALG, secret_key=private_key)
    signature = signer.sign_with_ctx_str(signing_input.encode(), CTX)

    token = f"{signing_input}.{_b64e(signature)}"
    return token


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
        The JWT‑style token to verify.
    now : int, optional
        Override the current time (Unix timestamp).  Useful for testing.

    Returns
    -------
    dict
        The original claims payload (without the ``iat`` and ``exp`` fields).

    Raises
    ------
    InvalidToken
        If the token is malformed, the signature is invalid, or the token has
        expired.
    """
    try:
        header_b64, claims_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(header_b64))
        claims_full = json.loads(_b64d(claims_b64))
        signature = _b64d(sig_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise InvalidToken("malformed token") from exc

    if header.get("alg") != ALG:
        raise InvalidToken("unexpected algorithm")

    signing_input = f"{header_b64}.{claims_b64}".encode()

    verifier = oqs.Signature(ALG)
    if not verifier.verify_with_ctx_str(signing_input, signature, CTX, public_key):
        raise InvalidToken("bad signature")

    current = time.time() if now is None else now
    if claims_full.get("exp", 0) < current:
        raise InvalidToken("expired")

    # Return only the user‑supplied claims, stripping the JWT‑specific fields.
    claims = {k: v for k, v in claims_full.items() if k not in ("iat", "exp")}
    return claims


# --------------------------------------------------------------------------- #
# Compatibility layer – mimicking the original ``jwt`` module API
# --------------------------------------------------------------------------- #
def encode(
    payload: Dict[str, Any],
    key: bytes,
    algorithm: str = ALG,
    ttl_seconds: int = 3600,
    **kwargs: Any,
) -> str:
    """
    Compatibility wrapper for the original ``jwt.encode`` API.

    Parameters
    ----------
    payload : dict
        Claims to embed.
    key : bytes
        Private key (as returned by :func:`generate_keypair`).
    algorithm : str, optional
        Must be ``ML-DSA-65``; any other value raises :class:`InvalidToken`.
    ttl_seconds : int, optional
        Token lifetime.
    **kwargs
        Ignored – present for API compatibility.

    Returns
    -------
    str
        JWT token.
    """
    if algorithm != ALG:
        raise InvalidToken(f"unsupported algorithm {algorithm}")
    return issue_token(key, payload, ttl_seconds=ttl_seconds, now=kwargs.get("now"))


def decode(
    token: str,
    key: bytes,
    algorithms: Tuple[str, ...] = (ALG,),
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Compatibility wrapper for the original ``jwt.decode`` API.

    Parameters
    ----------
    token : str
        JWT token.
    key : bytes
        Public key (as returned by :func:`generate_keypair`).
    algorithms : tuple[str, ...], optional
        Accepted algorithms; must contain ``ML-DSA-65``.
    **kwargs
        Ignored – present for API compatibility (e.g., ``options``).

    Returns
    -------
    dict
        The original claims payload.
    """
    if ALG not in algorithms:
        raise InvalidToken(f"algorithm {ALG} not allowed")
    return verify_token(key, token, now=kwargs.get("now"))


# Export the public names expected by the test suite.
__all__ = [
    "generate_keypair",
    "encode",
    "decode",
    "InvalidToken",
    "issue_token",
    "verify_token",
]
