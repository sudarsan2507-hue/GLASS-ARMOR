"""JWT-style signed API tokens (RS256: RSA PKCS#1 v1.5 with SHA-256).

token = base64url(header) "." base64url(claims) "." base64url(signature)
The signature covers "header.claims". The verifier only accepts the expected algorithm
and rejects expired tokens.
"""
import base64
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ALG = "RS256"


class InvalidToken(Exception):
    pass


def _b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the token issuer."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return public_bytes, private_bytes


def issue_token(private_key, claims, ttl_seconds=3600, now=None):
    """Return a signed token string for `claims` (a dict), valid for ttl_seconds."""
    now = int(time.time() if now is None else now)
    body = dict(claims, iat=now, exp=now + ttl_seconds)
    signing_input = _b64e(json.dumps({"alg": ALG, "typ": "JWT"}).encode()) + "." + \
        _b64e(json.dumps(body, sort_keys=True).encode())
    key = serialization.load_pem_private_key(private_key, password=None)
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
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
    if header.get("alg") != ALG:
        raise InvalidToken("unexpected algorithm")
    try:
        key = serialization.load_pem_public_key(public_key)
        key.verify(signature, (header_b64 + "." + claims_b64).encode(), padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError):
        raise InvalidToken("bad signature")
    if claims.get("exp", 0) < (time.time() if now is None else now):
        raise InvalidToken("expired")
    return claims
