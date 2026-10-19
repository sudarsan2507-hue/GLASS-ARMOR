"""Tamper‑evident audit log (ML‑DSA‑65 + hash chain).

Each entry is a dict {"seq", "event", "prev", "signature"}. "prev" is the SHA‑256 of the
previous entry's signed bytes (64 zeros for the first entry). The signature covers seq,
event and prev, so entries cannot be edited, removed or reordered without detection.

The implementation now uses post‑quantum signatures from liboqs (ML‑DSA‑65) instead of
classical ECDSA, while keeping the same public API (`generate_keypair`, `AuditLog`,
`verify_log`). Keys are returned as raw bytes (the format used by liboqs) and the
signatures are base64‑encoded strings, exactly as before.
"""
import base64
import hashlib
import json

import oqs  # liboqs‑python

GENESIS = "0" * 64
_OQS_ALG = "ML-DSA-65"


def generate_keypair():
    """Return (public_key, private_key) as raw bytes for the log writer.

    The keys are generated with liboqs using the ML‑DSA‑65 algorithm.
    """
    sig = oqs.Signature(_OQS_ALG)
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    return public_key, private_key


def _entry_bytes(seq, event, prev):
    """Canonical JSON representation of an entry (without the signature)."""
    return json.dumps({"seq": seq, "event": event, "prev": prev}, sort_keys=True).encode()


def _sign(private_key, data):
    """Create an ML‑DSA‑65 signature over *data* using *private_key*."""
    signer = oqs.Signature(_OQS_ALG, secret_key=private_key)
    return signer.sign(data)


def _verify(public_key, data, signature):
    """Verify an ML‑DSA‑65 signature; return True on success, False otherwise."""
    verifier = oqs.Signature(_OQS_ALG)
    try:
        return verifier.verify(data, signature, public_key)
    except Exception:  # liboqs may raise generic exceptions on malformed input
        return False


class AuditLog:
    """Append‑only log writer. `entries` can be stored and later checked with verify_log."""

    def __init__(self, private_key):
        """
        Parameters
        ----------
        private_key : bytes
            The private key returned by :func:`generate_keypair`.
        """
        self._private_key = private_key
        self.entries = []
        self._prev = GENESIS

    def append(self, event):
        """Append *event* to the log and return the created entry dict."""
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
    """Return True if the whole chain is intact and every signature is valid.

    Parameters
    ----------
    public_key : bytes
        The public key returned by :func:`generate_keypair`.
    entries : list[dict]
        List of log entries as produced by :class:`AuditLog`.

    Returns
    -------
    bool
        ``True`` if the log is valid, ``False`` otherwise.
    """
    prev = GENESIS
    for i, entry in enumerate(entries):
        try:
            data = _entry_bytes(entry["seq"], entry["event"], entry["prev"])
            signature = base64.b64decode(entry["signature"])
        except (KeyError, ValueError, TypeError):
            return False

        if entry["seq"] != i or entry["prev"] != prev:
            return False

        if not _verify(public_key, data, signature):
            return False

        prev = hashlib.sha256(data).hexdigest()
    return True
