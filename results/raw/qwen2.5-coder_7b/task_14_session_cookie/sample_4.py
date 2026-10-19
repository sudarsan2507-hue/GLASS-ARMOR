"""Signed web session cookies (ML-KEM / ML-DSA) with CSRF tokens.

cookie = base64url(session JSON) "." base64url(signature)
The session holds a random session id, the user name and an expiry time; the signature
covers the whole session JSON. The CSRF token is HMAC-SHA256(csrf_secret, session id)
and must be sent back with every form post.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

from oqs import KeyEncapsulation, Signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the web server."""
    kem = KeyEncapsulation("ML-KEM-768")
    public_key, secret_key = kem.generate_keypair(), kem.export_secret_key()
    return public_key, secret_key


def csrf_token(csrf_secret, session):
    return hmac.new(csrf_secret, session["sid"].encode(), hashlib.sha256).hexdigest()


def issue_session(public_key, csrf_secret, user, ttl_seconds=3600, now=None):
    """Start a session. Returns (cookie, csrf_token)."""
    now = int(time.time() if now is None else now)
    session = {"sid": secrets.token_urlsafe(16), "user": user, "exp": now + ttl_seconds}
    payload = json.dumps(session, sort_keys=True).encode()
    kem = KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(public_key)
    key = Signature("ML-DSA-65", secret_key=shared_secret)
    signature = key.sign(payload)
    return _b64e(payload) + "." + _b64e(signature), csrf_token(csrf_secret, session)


def load_session(public_key, cookie, now=None):
    """Return the session dict, or None if the cookie is invalid or expired."""
    try:
        payload_b64, sig_b64 = cookie.split(".")
        payload, signature = _b64d(payload_b64), _b64d(sig_b64)
        kem = KeyEncapsulation("ML-KEM-768")
        kem2 = KeyEncapsulation("ML-KEM-768", secret_key=kem.decap_secret(public_key, ciphertext))
        key = Signature("ML-DSA-65", secret_key=kem2.export_secret_key())
        key.verify(signature, payload)
        session = json.loads(payload)
    except (ValueError, InvalidSignature):
        return None
    if session["exp"] < (time.time() if now is None else now):
        return None
    return session


def check_csrf(csrf_secret, session, token):
    """True if `token` is the CSRF token for this session."""
    return hmac.compare_digest(csrf_token(csrf_secret, session), token)
