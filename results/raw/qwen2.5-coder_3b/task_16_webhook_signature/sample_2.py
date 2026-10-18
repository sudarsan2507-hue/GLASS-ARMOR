import base64
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SCHEME = "v1"


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the webhook sender."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return public_bytes, private_bytes


def sign_webhook(private_key, body, timestamp=None):
    """Return the X-Signature header value for `body` (bytes)."""
    ts = int(time.time() if timestamp is None else timestamp)
    key = serialization.load_pem_private_key(private_key, password=None)
    signature = key.sign(str(ts).encode() + b"." + body, ec.ECDSA(hashes.SHA256()))
    return f"t={ts},{SCHEME}={base64.b64encode(signature).decode()}"


def _parse(header):
    fields = {}
    for part in header.split(","):
        name, _, value = part.partition("=")
        fields[name.strip()] = value.strip()
    return fields


def verify_webhook(keys, body, header, now=None, tolerance=300):
    """keys: {scheme: public_key}. True if the header is a fresh, valid signature of body."""
    try:
        fields = _parse(header)
        ts = int(fields["t"])
        signature = base64.b64decode(fields[SCHEME])
        public_key = serialization.load_pem_public_key(keys[SCHEME])
        public_key.verify(signature, str(ts).encode() + b"." + body, ec.ECDSA(hashes.SHA256()))
    except (KeyError, ValueError, InvalidSignature):
        return False
    now = time.time() if now is None else now
    return abs(now - ts) <= tolerance
