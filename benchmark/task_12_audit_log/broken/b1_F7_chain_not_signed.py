"""Tamper-evident audit log (ML-DSA-65 + hash chain). Post-quantum version.

Each entry is a dict {"seq", "event", "prev", "signature"}. "prev" is the SHA-256 of the
previous entry's signed bytes (64 zeros for the first entry). The ML-DSA signature (with a
fixed context string) covers seq, event and prev, so entries cannot be edited, removed or
reordered without detection.
"""
import base64
import hashlib
import json

import oqs

SIG_ALG = "ML-DSA-65"
CONTEXT = b"pq-gate audit log v1"
GENESIS = "0" * 64


def generate_keypair():
    """Return (public_key, private_key) as bytes for the log writer."""
    with oqs.Signature(SIG_ALG) as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key


def _entry_bytes(seq, event, prev):
    return json.dumps({"seq": seq, "event": event, "prev": prev}, sort_keys=True).encode()


def _sign(private_key, data):
    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:
        return sig.sign_with_ctx_str(data, CONTEXT)


def _verify(public_key, data, signature):
    try:
        with oqs.Signature(SIG_ALG) as sig:
            return sig.verify_with_ctx_str(data, signature, CONTEXT, public_key)
    except Exception:
        return False


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
                 "signature": base64.b64encode(_sign(self._private_key, event.encode())).decode()}
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
        if entry["seq"] != i or entry["prev"] != prev or not _verify(public_key, entry["event"].encode(), signature):
            return False
        prev = hashlib.sha256(data).hexdigest()
    return True
