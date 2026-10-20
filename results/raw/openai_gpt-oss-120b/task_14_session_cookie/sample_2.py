"""Signed web session cookies (ML‑DSA‑65) with CSRF tokens.

cookie = base64url(session JSON) "." base64url(signature)
The session holds a random session id, the user name and an expiry time; the signature
covers the whole session JSON. The CSRF token is HMAC‑SHA256(csrf_secret, session id)
and must be sent back with every form post.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

import oqs  # liboqs‑python

# --------------------------------------------------------------------------- #
# Helper functions for URL‑safe base64 without padding
# --------------------------------------------------------------------------- #
def _b64e(data: bytes) -> str:
    """Encode *data* using URL‑safe base64 without trailing ``=`` padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Decode a URL‑safe base64 string that may be missing padding."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- #
# Key handling (ML‑DSA‑65)
# --------------------------------------------------------------------------- #
def generate_keypair():
    """Return ``(public_key, private_key)`` as raw bytes for the web server.

    The keys are generated with the post‑quantum signature scheme
    **ML‑DSA‑65** provided by liboqs.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# CSRF handling (unchanged)
# --------------------------------------------------------------------------- #
def csrf_token(csrf_secret: bytes, session: dict) -> str:
    """Return the CSRF token for *session*."""
    return hmac.new(csrf_secret, session["sid"].encode(), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# Session issuance
# --------------------------------------------------------------------------- #
def issue_session(private_key: bytes, csrf_secret: bytes, user: str,
                  ttl_seconds: int = 3600, now: int | None = None):
    """Start a session. Returns ``(cookie, csrf_token)``.

    * ``private_key`` – the ML‑DSA‑65 secret key returned by :func:`generate_keypair`.
    * ``csrf_secret`` – secret used for HMAC‑based CSRF tokens.
    * ``user`` – identifier stored in the session.
    * ``ttl_seconds`` – how long the session is valid.
    * ``now`` – optional override for the current timestamp (useful for testing).
    """
    now = int(time.time() if now is None else now)
    session = {
        "sid": secrets.token_urlsafe(16),
        "user": user,
        "exp": now + ttl_seconds,
    }

    payload = json.dumps(session, sort_keys=True).encode()

    # Sign with ML‑DSA‑65
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    signature = signer.sign(payload)

    cookie = f"{_b64e(payload)}.{_b64e(signature)}"
    return cookie, csrf_token(csrf_secret, session)


# --------------------------------------------------------------------------- #
# Session loading / verification
# --------------------------------------------------------------------------- #
def load_session(public_key: bytes, cookie: str, now: int | None = None):
    """Return the session dict, or ``None`` if the cookie is invalid or expired.

    * ``public_key`` – the ML‑DSA‑65 public key returned by :func:`generate_keypair`.
    * ``cookie`` – the value produced by :func:`issue_session`.
    """
    try:
        payload_b64, sig_b64 = cookie.split(".")
        payload = _b64d(payload_b64)
        signature = _b64d(sig_b64)

        verifier = oqs.Signature("ML-DSA-65")
        if not verifier.verify(payload, signature, public_key):
            return None

        session = json.loads(payload)
    except (ValueError, json.JSONDecodeError):
        # ValueError covers malformed base64 or missing dot.
        return None

    # Expiration check
    current = int(time.time() if now is None else now)
    if session.get("exp", 0) < current:
        return None

    return session


# --------------------------------------------------------------------------- #
# CSRF verification (unchanged)
# --------------------------------------------------------------------------- #
def check_csrf(csrf_secret: bytes, session: dict, token: str) -> bool:
    """Return ``True`` if *token* matches the CSRF token for *session*."""
    return hmac.compare_digest(csrf_token(csrf_secret, session), token)
