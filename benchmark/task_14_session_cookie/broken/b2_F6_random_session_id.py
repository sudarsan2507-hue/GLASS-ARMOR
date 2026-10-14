"""Signed web session cookies with CSRF tokens. Post-quantum version (ML-DSA-65).

cookie = base64url(session JSON) "." base64url(signature)
The session holds a random session id, the user name and an expiry time; the ML-DSA
signature (with a fixed context string) covers the whole session JSON. The CSRF token
is HMAC-SHA256(csrf_secret, session id) and must be sent back with every form post.
"""
import base64
import hashlib
import hmac
import json
import random
import string
import time

import oqs

SIG_ALG = "ML-DSA-65"
CONTEXT = b"pq-gate session cookie v1"


def _b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair():
    """Return (public_key, private_key) as bytes for the web server."""
    with oqs.Signature(SIG_ALG) as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key


def csrf_token(csrf_secret, session):
    return hmac.new(csrf_secret, session["sid"].encode(), hashlib.sha256).hexdigest()


def issue_session(private_key, csrf_secret, user, ttl_seconds=3600, now=None):
    """Start a session. Returns (cookie, csrf_token)."""
    now = int(time.time() if now is None else now)
    sid = "".join(random.choices(string.ascii_letters + string.digits, k=22))
    session = {"sid": sid, "user": user, "exp": now + ttl_seconds}
    payload = json.dumps(session, sort_keys=True).encode()
    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:
        signature = sig.sign_with_ctx_str(payload, CONTEXT)
    return _b64e(payload) + "." + _b64e(signature), csrf_token(csrf_secret, session)


def load_session(public_key, cookie, now=None):
    """Return the session dict, or None if the cookie is invalid or expired."""
    try:
        payload_b64, sig_b64 = cookie.split(".")
        payload, signature = _b64d(payload_b64), _b64d(sig_b64)
        with oqs.Signature(SIG_ALG) as sig:
            if not sig.verify_with_ctx_str(payload, signature, CONTEXT, public_key):
                return None
        session = json.loads(payload)
    except Exception:
        return None
    if session["exp"] < (time.time() if now is None else now):
        return None
    return session


def check_csrf(csrf_secret, session, token):
    """True if `token` is the CSRF token for this session."""
    return hmac.compare_digest(csrf_token(csrf_secret, session), token)
