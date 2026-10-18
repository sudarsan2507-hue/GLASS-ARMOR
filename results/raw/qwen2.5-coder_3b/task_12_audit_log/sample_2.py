import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes, asymmetric

GENESIS = "0" * 64


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the log writer."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return public_bytes, private_bytes


def _entry_bytes(seq, event, prev):
    return json.dumps({"seq": seq, "event": event, "prev": prev}, sort_keys=True).encode()


def _sign(private_key, data):
    key = serialization.load_pem_private_key(private_key, password=None)
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def _verify(public_key, data, signature):
    try:
        serialization.load_pem_public_key(public_key).verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def _hkdf_extract(salt, ikm):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"").derive(ikm)


def _hkdf_expand(tok, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(tok)


class AuditLog:
    """Append-only log writer. `entries` can be stored and later checked with verify_log."""

    def __init__(self, private_key):
        self._private_key = private_key
        self.entries = []
        self._prev = GENESIS

    def append(self, event):
        seq = len(self.entries)
        data = _entry_bytes(seq, event, self._prev)
        entry = {"seq": seq, "event": event, "prev": self._prev,
                 "signature": base64.b64encode(_sign(self._private_key, data)).decode()}
        self.entries.append(entry)
        self._prev = hashlib.sha256(data).hexdigest()
        return entry


def verify_log(public_key, entries):
    """Return True if the whole chain is intact and every signature is valid."""
    prev = GENESIS
    for i, entry in enumerate(entries):
        try:
            data = _entry_bytes(entry["seq"], entry["event"], entry["prev"])
            signature = base64.b64decode(entry["signature"])
        except (KeyError, ValueError):
            return False
        if entry["seq"] != i or entry["prev"] != prev or not _verify(public_key, data, signature):
            return False
        prev = hashlib.sha256(data).hexdigest()
    return True
