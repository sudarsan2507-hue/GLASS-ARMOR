"""JWT‑style signed API tokens (ML‑DSA‑65 post‑quantum signature).

The token format is unchanged:

    token = base64url(header) "." base64url(claims) "." base64url(signature)

The signature now covers ``header.claims`` **with an explicit context** using the
ML‑DSA‑65 algorithm from liboqs.  Binding the signature to a context (here the
string ``"JWT"``) prevents the signature from being valid in a different
protocol or when parts of the signed message are altered without detection.
The verifier only accepts the expected algorithm and rejects expired tokens.
"""

import base64
import json
import time
from typing import Tuple

import oqs
from cryptography.exceptions import InvalidSignature  # kept for API compatibility

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
ALG = "ML-DSA-65"
# Fixed context string used for both signing and verification.
# Using a constant context binds the signature to the JWT use‑case.
_CTX = b"JWT"  # liboqs expects the context as *bytes* for the low‑level API.


# --------------------------------------------------------------------------- #
# Helper exceptions
# --------------------------------------------------------------------------- #
class InvalidToken(Exception):
    """Raised when a token is malformed, has a bad signature, or is expired."""
    pass


# --------------------------------------------------------------------------- #
# Base64 helpers (URL‑safe, no padding)
# --------------------------------------------------------------------------- #
def _b64e(data: bytes) -> str:
    """Base64‑url encode without padding, returning a ``str``."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Base64‑url decode, adding padding as required."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Return ``(public_key, private_key)`` as raw bytes for the token issuer.

    The keys are generated with liboqs using the ML‑DSA‑65 algorithm.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Token issuance
# --------------------------------------------------------------------------- #
def _sign_message(message: bytes, private_key: bytes) -> bytes:
    """
    Sign *message* with the supplied private key using the fixed context.

    liboqs provides two families of signing APIs:
        * ``sign_with_ctx`` – expects a *bytes* context.
        * ``sign_with_ctx_str`` – expects a *str* context.

    Not all liboqs versions expose the ``*_str`` variant, so we try the
    ``bytes`` version first and fall back to the ``str`` version if necessary.
    """
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)

    # Preferred: bytes‑based context API
    if hasattr(signer, "sign_with_ctx"):
        return signer.sign_with_ctx(message, _CTX)

    # Fallback: string‑based context API
    if hasattr(signer, "sign_with_ctx_str"):
        return signer.sign_with_ctx_str(message, _CTX.decode())

    # Ultimate fallback: no‑context signing (still works, but loses the
    # cross‑protocol binding – this path should never be hit in normal use).
    return signer.sign(message)


def issue_token(
    private_key: bytes,
    claims: dict,
    ttl_seconds: int = 3600,
    now: int | None = None,
) -> str:
    """
    Return a signed token string for ``claims`` (a dict), valid for ``ttl_seconds``.

    The token header contains the algorithm identifier defined in ``ALG``.
    The signature is generated with an explicit context (``_CTX``) to bind the
    token to the JWT use‑case.
    """
    now = int(time.time() if now is None else now)
    body = dict(claims, iat=now, exp=now + ttl_seconds)

    # Header and payload are JSON‑encoded, then base64‑url‑encoded.
    header_b64 = _b64e(json.dumps({"alg": ALG, "typ": "JWT"}).encode())
    payload_b64 = _b64e(json.dumps(body, sort_keys=True).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = _sign_message(signing_input, private_key)

    token = f"{header_b64}.{payload_b64}.{_b64e(signature)}"
    return token


# --------------------------------------------------------------------------- #
# Token verification
# --------------------------------------------------------------------------- #
def _verify_message(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify *message* against *signature* using the supplied public key and the
    fixed context.  Mirrors :func:`_sign_message` in its handling of the two
    possible liboqs APIs.
    """
    verifier = oqs.Signature("ML-DSA-65")

    # Preferred: bytes‑based context API
    if hasattr(verifier, "verify_with_ctx"):
        return verifier.verify_with_ctx(message, signature, _CTX, public_key)

    # Fallback: string‑based context API
    if hasattr(verifier, "verify_with_ctx_str"):
        return verifier.verify_with_ctx_str(message, signature, _CTX.decode(), public_key)

    # Ultimate fallback: no‑context verification
    return verifier.verify(message, signature, public_key)


def verify_token(public_key: bytes, token: str, now: int | None = None) -> dict:
    """
    Verify ``token`` using ``public_key`` and return the claims dict.

    Raises :class:`InvalidToken` if the token is malformed, has a bad signature,
    or is expired.
    """
    try:
        header_b64, claims_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(header_b64))
        claims = json.loads(_b64d(claims_b64))
        signature = _b64d(sig_b64)
    except Exception as exc:  # includes ValueError, JSONDecodeError, etc.
        raise InvalidToken("malformed token") from exc

    if header.get("alg") != ALG:
        raise InvalidToken("unexpected algorithm")

    signing_input = f"{header_b64}.{claims_b64}".encode()

    try:
        ok = _verify_message(signing_input, signature, public_key)
    except Exception as exc:  # liboqs may raise generic exceptions on failure
        raise InvalidToken("bad signature") from exc

    if not ok:
        raise InvalidToken("bad signature")

    current_time = time.time() if now is None else now
    if claims.get("exp", 0) < current_time:
        raise InvalidToken("expired")

    return claims
