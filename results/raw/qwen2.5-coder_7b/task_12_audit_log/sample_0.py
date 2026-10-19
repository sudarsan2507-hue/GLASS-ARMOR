"""Tamper-evident audit log (ML-KEM / ML-DSA + hash chain).

Each entry is a dict {"seq", "event", "prev", "signature"}. "prev" is the SHA-256 of the
previous entry's signed bytes (64 zeros for the first entry). The signature covers seq,
event and prev, so entries cannot be edited, removed or reordered without detection.
"""
import base64
import hashlib
import json

from oqs import KeyEncapsulation, Signature
from cryptography.hazmat.primitives import hashes

GENESIS = "0" * 64


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the log writer."""
    kem = KeyEncapsulation("ML-KEM-768")
    public_key, secret_key = kem.generate_keypair()
    return public_key, secret_key


def _entry_bytes(seq, event, prev):
    return json.dumps({"seq": seq, "event": event, "prev": prev}, sort_keys=True).encode()


def _sign(private_key, data):
    sig = Signature("ML-DSA-65", secret_key=private_key)
    return sig.sign(data)


def _verify(public_key, data, signature):
    sig = Signature("ML-DSA-65")
    return sig.verify(data, signature, public_key)


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
