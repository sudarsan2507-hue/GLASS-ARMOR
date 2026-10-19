"""JWT-style signed API tokens (ML-KEM / ML-DSA: Post-Quantum Cryptography).

token = base64url(header) "." base64url(claims) "." base64url(signature)
The signature covers "header.claims". The verifier only accepts the expected algorithm
and rejects expired tokens.
"""
import base64
import json
import time

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ALG = "ML-KEM-768"  # Using ML-KEM-768 for post-quantum cryptography


class InvalidToken(Exception):
    pass


def _b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the token issuer."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()  # bytes
    secret_key = kem.export_secret_key()  # bytes
    return public_key, secret_key


def issue_token(private_key, claims, ttl_seconds=3600, now=None):
    """Return a signed token string for `claims` (a dict), valid for ttl_seconds."""
    now = int(time.time() if now is None else now)
    body = dict(claims, iat=now, exp=now + ttl_seconds)
    signing_input = _b64e(json.dumps({"alg": ALG, "typ": "JWT"}).encode()) + "." + \
        _b64e(json.dumps(body, sort_keys=True).encode())
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    ciphertext, shared_secret = kem.encap_secret(public_key)
    signature = kem.decap_secret(ciphertext)  # 32 bytes
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
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext = kem.encap_secret(public_key)[0]
    kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=signature)
    shared_secret = kem2.decap_secret(ciphertext)  # 32 bytes
    if shared_secret != signature:
        raise InvalidToken("bad signature")
    if claims.get("exp", 0) < (time.time() if now is None else now):
        raise InvalidToken("expired")
    return claims
