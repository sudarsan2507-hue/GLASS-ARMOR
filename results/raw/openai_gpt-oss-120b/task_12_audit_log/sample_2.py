"""Tamper‑evident audit log (ML‑DSA‑65 + hash chain).

Each entry is a dict {"seq", "event", "prev", "signature"}. "prev" is the SHA‑256 of the
previous entry's signed bytes (64 zeros for the first entry). The signature covers seq,
event and prev, so entries cannot be edited, removed or reordered without detection.
"""

import base64
import hashlib
import json

import oqs

GENESIS = "0" * 64


def generate_keypair():
    """Return (public_key, private_key) as raw bytes for the log writer.

    The keys are generated with the post‑quantum signature scheme ML‑DSA‑65.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    return public_key, private_key


def _entry_bytes(seq, event, prev):
    """Canonical JSON representation of an entry (without the signature)."""
    return json.dumps({"seq": seq, "event": event, "prev": prev}, sort_keys=True).encode()


def _sign(private_key, data):
    """Create an ML‑DSA‑65 signature over *data* using *private_key*."""
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    return signer.sign(data)


def _verify(public_key, data, signature):
    """Verify an ML‑DSA‑65 signature; return True on success, False otherwise."""
    verifier = oqs.Signature("ML-DSA-65")
    try:
        return verifier.verify(data, signature, public_key)
    except Exception:  # liboqs may raise on malformed inputs
        return False


class AuditLog:
    """Append‑only log writer. `entries` can be stored and later checked with verify_log."""

    def __init__(self, private_key):
        self._private_key = private_key
        self.entries = []
        self._prev = GENESIS

    def append(self, event):
        """Append a new *event* to the log and return the created entry."""
        seq = len(self.entries)
        data = _entry_bytes(seq, event, self._prev)
        signature = _sign(self._private_key, data)
        entry = {
            "seq": seq,
            "event": event,
            "prev": self._prev,
            "signature": base64.b64encode(signature).decode(),
        }
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
        except (KeyError, ValueError, TypeError):
            return False
        if entry["seq"] != i or entry["prev"] != prev or not _verify(public_key, data, signature):
            return False
        prev = hashlib.sha256(data).hexdigest()
    return True
