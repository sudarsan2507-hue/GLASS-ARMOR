"""JWT‑style signed API tokens (ML‑DSA‑65 post‑quantum signature).

The token format is unchanged:

    token = base64url(header) "." base64url(claims) "." base64url(signature)

The signature now covers "header.claims" using the ML‑DSA‑65 algorithm from liboqs.
The verifier only accepts the expected algorithm and rejects expired tokens.
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
    """Base64‑url encode without padding, returning a str."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Base64‑url decode, adding padding as required."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair():
    """
    Return ``(public_key, private_key)`` as raw bytes for the token issuer.

    The keys are generated with liboqs using the ML‑DSA‑65 algorithm.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    return public_key, private_key


def issue_token(private_key: bytes, claims: dict, ttl_seconds: int = 3600, now: int | None = None) -> str:
    """
    Return a signed token string for ``claims`` (a dict), valid for ``ttl_seconds``.

    The token header contains the algorithm identifier defined in ``ALG``.
    """
    now = int(time.time() if now is None else now)
    body = dict(claims, iat=now, exp=now + ttl_seconds)

    # Header and payload are JSON‑encoded, then base64‑url‑encoded.
    header_b64 = _b64e(json.dumps({"alg": ALG, "typ": "JWT"}).encode())
    payload_b64 = _b64e(json.dumps(body, sort_keys=True).encode())
    signing_input = f"{header_b64}.{payload_b64}"

    # Sign with ML‑DSA‑65.
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    signature = signer.sign(signing_input.encode())  # bytes

    token = f"{signing_input}.{_b64e(signature)}"
    return token


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
    except ValueError as exc:
        raise InvalidToken("malformed token") from exc

    if header.get("alg") != ALG:
        raise InvalidToken("unexpected algorithm")

    signing_input = f"{header_b64}.{claims_b64}".encode()

    verifier = oqs.Signature("ML-DSA-65")
    try:
        ok = verifier.verify(signing_input, signature, public_key)
    except Exception as exc:  # liboqs may raise generic exceptions on failure
        raise InvalidToken("bad signature") from exc

    if not ok:
        raise InvalidToken("bad signature")

    current_time = time.time() if now is None else now
    if claims.get("exp", 0) < current_time:
        raise InvalidToken("expired")

    return claims
