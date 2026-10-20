"""JWT‑style signed API tokens (ML‑DSA‑65 post‑quantum signature).

The token format is unchanged:

    token = base64url(header) "." base64url(claims) "." base64url(signature)

The signature now covers "header.claims" using the ML‑DSA‑65 algorithm from
liboqs. Public functions keep the same signatures as the original RSA
implementation so existing tests continue to work.
"""
import base64
import json
import time

import oqs
from cryptography.exceptions import InvalidSignature  # kept for API compatibility

ALG = "ML-DSA-65"


class InvalidToken(Exception):
    """Raised when a token is malformed, has a bad signature, or is expired."""
    pass


def _b64e(data: bytes) -> str:
    """Base64‑url encode without padding, returning a ``str``."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Base64‑url decode that tolerates missing padding."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- #
# Key handling (ML‑DSA‑65)
# --------------------------------------------------------------------------- #
def generate_keypair():
    """
    Return ``(private_key, public_key)`` as raw bytes for the token issuer.

    The keys are generated with liboqs's ``ML-DSA-65`` algorithm. They are
    *not* PEM‑encoded – the calling code only needs the byte strings to pass
    back to :func:`issue_token` and :func:`verify_token`.
    """
    sig = oqs.Signature(ALG)
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    # ``sig`` can be discarded; the raw key material is all we need.
    return private_key, public_key


# --------------------------------------------------------------------------- #
# Token issuance
# --------------------------------------------------------------------------- #
def issue_token(private_key: bytes, claims: dict, ttl_seconds: int = 3600, now: int | None = None) -> str:
    """
    Return a signed token string for ``claims`` (a ``dict``), valid for
    ``ttl_seconds`` seconds.

    ``private_key`` must be the raw secret key bytes produced by
    :func:`generate_keypair`.
    """
    now = int(time.time() if now is None else now)
    body = dict(claims, iat=now, exp=now + ttl_seconds)

    # Header and payload are JSON‑encoded, then base64url‑encoded.
    header_b64 = _b64e(json.dumps({"alg": ALG, "typ": "JWT"}).encode())
    payload_b64 = _b64e(json.dumps(body, sort_keys=True).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # Sign with ML‑DSA‑65.
    signer = oqs.Signature(ALG, secret_key=private_key)
    signature = signer.sign(signing_input)

    token = f"{header_b64}.{payload_b64}.{_b64e(signature)}"
    return token


# --------------------------------------------------------------------------- #
# Token verification
# --------------------------------------------------------------------------- #
def verify_token(public_key: bytes, token: str, now: int | None = None) -> dict:
    """
    Verify ``token`` using ``public_key`` (raw bytes from :func:`generate_keypair`).

    Returns the claims ``dict`` if verification succeeds, otherwise raises
    :class:`InvalidToken`.
    """
    try:
        header_b64, claims_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(header_b64))
        claims = json.loads(_b64d(claims_b64))
        signature = _b64d(sig_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise InvalidToken("malformed token") from exc

    # Algorithm check – we only accept ML‑DSA‑65.
    if header.get("alg") != ALG:
        raise InvalidToken("unexpected algorithm")

    # Verify the signature.
    verifier = oqs.Signature(ALG)  # no secret key needed for verification
    signing_input = f"{header_b64}.{claims_b64}".encode()
    try:
        ok = verifier.verify(signing_input, signature, public_key)
    except Exception as exc:  # liboqs may raise ValueError for malformed signatures
        raise InvalidToken("bad signature") from exc

    if not ok:
        raise InvalidToken("bad signature")

    # Expiration check.
    current = int(time.time() if now is None else now)
    if claims.get("exp", 0) < current:
        raise InvalidToken("expired")

    return claims
