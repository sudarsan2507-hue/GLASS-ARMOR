"""Signed web session cookies (ML‑DSA‑65) with CSRF tokens.

cookie = base64url(session JSON) "." base64url(signature)
The session holds a random session id, the user name and an expiry time; the signature
covers the whole session JSON. The CSRF token is HMAC‑SHA256(csrf_secret, session id)
and must be sent back with every form post.

This module mirrors the original API but uses the post‑quantum signature scheme
ML‑DSA‑65 from liboqs instead of ECDSA‑P‑256.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Tuple, Optional

import oqs
from cryptography.exceptions import InvalidSignature  # kept for compatibility with callers


# --------------------------------------------------------------------------- #
# Helper functions for URL‑safe base64 encoding/decoding
# --------------------------------------------------------------------------- #
def _b64e(data: bytes) -> str:
    """Encode bytes to URL‑safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    """Decode URL‑safe base64 (adding padding if necessary)."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- #
# Key handling (ML‑DSA‑65)
# --------------------------------------------------------------------------- #
def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a ML‑DSA‑65 key pair.

    Returns
    -------
    (public_key, private_key) as raw bytes.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    return public_key, private_key


# --------------------------------------------------------------------------- #
# CSRF handling (unchanged)
# --------------------------------------------------------------------------- #
def csrf_token(csrf_secret: bytes, session: dict) -> str:
    """Return the HMAC‑SHA256 CSRF token for a given session."""
    return hmac.new(csrf_secret, session["sid"].encode(), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# Session issuance
# --------------------------------------------------------------------------- #
def issue_session(
    private_key: bytes,
    csrf_secret: bytes,
    user: str,
    ttl_seconds: int = 3600,
    now: Optional[int] = None,
) -> Tuple[str, str]:
    """
    Create a new signed session cookie.

    Parameters
    ----------
    private_key : bytes
        The ML‑DSA‑65 private key (as returned by ``generate_keypair``).
    csrf_secret : bytes
        Secret used for CSRF token generation.
    user : str
        Username to embed in the session.
    ttl_seconds : int, optional
        Lifetime of the session in seconds (default 3600).
    now : int, optional
        Override current time (Unix timestamp) – useful for testing.

    Returns
    -------
    (cookie, csrf_token) where ``cookie`` is the base64url‑encoded payload and
    signature separated by a dot, and ``csrf_token`` is the HMAC token string.
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
def load_session(
    public_key: bytes,
    cookie: str,
    now: Optional[int] = None,
) -> Optional[dict]:
    """
    Verify a session cookie and return the decoded session dict.

    Parameters
    ----------
    public_key : bytes
        The ML‑DSA‑65 public key (as returned by ``generate_keypair``).
    cookie : str
        The session cookie string ``payload.signature`` (base64url encoded).
    now : int, optional
        Override current time (Unix timestamp) – useful for testing.

    Returns
    -------
    dict or None
        The session dictionary if verification succeeds and the session has not
        expired; otherwise ``None``.
    """
    try:
        payload_b64, sig_b64 = cookie.split(".")
        payload = _b64d(payload_b64)
        signature = _b64d(sig_b64)

        verifier = oqs.Signature("ML-DSA-65")
        if not verifier.verify(payload, signature, public_key):
            raise InvalidSignature  # mimic cryptography's exception type
        session = json.loads(payload)
    except (ValueError, InvalidSignature, json.JSONDecodeError):
        return None

    # Expiry check
    expiry = session.get("exp")
    if expiry is None:
        return None
    if expiry < (time.time() if now is None else now):
        return None

    return session


# --------------------------------------------------------------------------- #
# CSRF token verification
# --------------------------------------------------------------------------- #
def check_csrf(csrf_secret: bytes, session: dict, token: str) -> bool:
    """
    Validate that ``token`` matches the CSRF token for ``session``.
    """
    return hmac.compare_digest(csrf_token(csrf_secret, session), token)
