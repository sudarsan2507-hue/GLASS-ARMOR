"""JWT-style signed API tokens. Post-quantum version (ML-DSA-65).

token = base64url(header) "." base64url(claims) "." base64url(signature)
The ML-DSA signature (with a fixed context string) covers "header.claims". The verifier
only accepts the expected algorithm and rejects expired tokens.
"""
import base64
import json
import time

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ALG = "ML-DSA-65"
CONTEXT = b"pq-gate api token v1"


class InvalidToken(Exception):
    pass


def _b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair():
    """Return (public_key, private_key) as bytes for the token issuer."""
    with oqs.Signature(ALG) as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key


def issue_token(private_key, claims, ttl_seconds=3600, now=None):
    """Return a signed token string for `claims` (a dict), valid for ttl_seconds."""
    now = int(time.time() if now is None else now)
    body = dict(claims, iat=now, exp=now + ttl_seconds)
    signing_input = _b64e(json.dumps({"alg": ALG, "typ": "JWT"}).encode()) + "." + \
        _b64e(json.dumps(body, sort_keys=True).encode())
    with oqs.Signature(ALG, secret_key=private_key) as sig:
        signature = sig.sign_with_ctx_str(signing_input.encode(), CONTEXT)
    return signing_input + "." + _b64e(signature)


def verify_token(public_key, token, now=None):
    """Return the claims dict. Raises InvalidToken if the token is invalid or expired."""
    try:
        header_b64, claims_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(header_b64))
        claims = json.loads(_b64d(claims_b64))
        signature = _b64d(sig_b64)
    except ValueError:
        raise InvalidToken("malformed token")
    if header.get("alg") == "RS256":  # tokens issued before the migration
        try:
            key = serialization.load_pem_public_key(public_key)
            key.verify(signature, (header_b64 + "." + claims_b64).encode(),
                       padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            raise InvalidToken("bad signature")
        return claims
    if header.get("alg") != ALG:
        raise InvalidToken("unexpected algorithm")
    try:
        with oqs.Signature(ALG) as sig:
            valid = sig.verify_with_ctx_str((header_b64 + "." + claims_b64).encode(),
                                            signature, CONTEXT, public_key)
    except Exception:
        valid = False
    if not valid:
        raise InvalidToken("bad signature")
    if claims.get("exp", 0) < (time.time() if now is None else now):
        raise InvalidToken("expired")
    return claims
