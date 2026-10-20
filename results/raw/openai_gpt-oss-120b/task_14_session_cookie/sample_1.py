"""Signed web session cookies (ML‑DSA‑65) with CSRF tokens.

cookie = base64url(session JSON) "." base64url(signature)
The session holds a random session id, the user name and an expiry time; the signature
covers the whole session JSON. The CSRF token is HMAC‑SHA256(csrf_secret, session id)
and must be sent back with every form post.

This module mirrors the original API that used ECDSA‑P256, but now uses the
post‑quantum signature scheme ML‑DSA‑65 from liboqs.  The public functions keep
the same signatures so existing tests continue to work.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

import oqs
from cryptography.exceptions import InvalidSignature  # kept for backward compatibility


def _b64e(data: bytes) -> str:
    """Base64‑url encode without padding, returning a string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Base64‑url decode a string that may be missing padding."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair():
    """Return (public_key, private_key) as raw bytes for the web server.

    The keys are generated with the ML‑DSA‑65 post‑quantum signature scheme.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    return public_key, private_key


def csrf_token(csrf_secret: bytes, session: dict) -> str:
    """Derive a CSRF token from the secret and the session identifier."""
    return hmac.new(csrf_secret, session["sid"].encode(), hashlib.sha256).hexdigest()


def issue_session(private_key: bytes, csrf_secret: bytes, user: str,
                  ttl_seconds: int = 3600, now: int | None = None):
    """Start a session. Returns (cookie, csrf_token).

    The cookie format is ``base64url(payload).base64url(signature)`` where the
    payload is the JSON representation of the session and the signature is
    produced with ML‑DSA‑65.
    """
    now = int(time.time() if now is None else now)
    session = {
        "sid": secrets.token_urlsafe(16),
        "user": user,
        "exp": now + ttl_seconds,
    }
    payload = json.dumps(session, sort_keys=True).encode()

    # Sign with the private key using ML‑DSA‑65
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    signature = signer.sign(payload)

    cookie = f"{_b64e(payload)}.{_b64e(signature)}"
    return cookie, csrf_token(csrf_secret, session)


def load_session(public_key: bytes, cookie: str, now: int | None = None):
    """Return the session dict, or ``None`` if the cookie is invalid or expired."""
    try:
        payload_b64, sig_b64 = cookie.split(".")
        payload = _b64d(payload_b64)
        signature = _b64d(sig_b64)

        verifier = oqs.Signature("ML-DSA-65")
        if not verifier.verify(payload, signature, public_key):
            return None

        session = json.loads(payload)
    except (ValueError, json.JSONDecodeError, InvalidSignature):
        # ``InvalidSignature`` is kept for compatibility with the old API;
        # it will never be raised by liboqs but may be raised by callers that
        # still import it.
        return None

    # Expiry check
    current = int(time.time() if now is None else now)
    if session.get("exp", 0) < current:
        return None
    return session


def check_csrf(csrf_secret: bytes, session: dict, token: str) -> bool:
    """Return ``True`` if ``token`` matches the CSRF token for ``session``."""
    return hmac.compare_digest(csrf_token(csrf_secret, session), token)
