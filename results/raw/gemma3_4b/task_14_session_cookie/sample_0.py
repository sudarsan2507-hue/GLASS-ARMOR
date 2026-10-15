"""Signed web session cookies (ECDSA P-256) with CSRF tokens.

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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the web server."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return public_bytes, private_bytes


def csrf_token(csrf_secret, session):
    return hmac.new(csrf_secret, session["sid"].encode(), hashlib.sha256).hexdigest()


def issue_session(private_key, csrf_secret, user, ttl_seconds=3600, now=None):
    """Start a session. Returns (cookie, csrf_token)."""
    now = int(time.time() if now is None else now)
    session = {"sid": secrets.token_urlsafe(16), "user": user, "exp": now + ttl_seconds}
    payload = json.dumps(session, sort_keys=True).encode()
    key = serialization.load_pem_private_key(private_key, password=None)
    signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    return _b64e(payload) + "." + _b64e(signature), csrf_token(csrf_secret, session)


def load_session(public_key, cookie, now=None):
    """Return the session dict, or None if the cookie is invalid or expired."""
    try:
        payload_b64, sig_b64 = cookie.split(".")
        payload, signature = _b64d(payload_b64), _b64d(sig_b64)
        serialization.load_pem_public_key(public_key).verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        session = json.loads(payload)
    except (ValueError, InvalidSignature):
        return None
    if session["exp"] < (time.time() if now is None else now):
        return None
    return session


def check_csrf(csrf_secret, session, token):
    """True if `token` is the CSRF token for this session."""
    return hmac.compare_digest(csrf_token(csrf_secret, session), token)


def generate_keypair_post_quantum():
    """Return (public_key, private_key) as PEM bytes for the web server using ML-KEM/ML-DSA."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key, private_key = kem.generate_keypair()
    return public_key, private_key


def sign_message_post_quantum(message, private_key):
    """Sign a message using ML-DSA."""
    sig = oqs.Signature("ML-DSA-65", secret_key=private_key)
    signature = sig.sign(message)
    return signature


def verify_signature_post_quantum(message, signature, public_key):
    """Verify a signature using ML-DSA."""
    sig = oqs.Signature("ML-DSA-65", secret_key=None)
    ok = sig.verify(message, signature, public_key)
    return ok


def generate_hkdf_key(context):
    """Generate an HKDF key from a context."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context)
    return hkdf.derive(b"...")
