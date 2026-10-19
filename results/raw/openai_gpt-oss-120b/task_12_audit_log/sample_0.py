"""Tamper‑evident audit log (ML‑DSA‑65 + hash chain).

Each entry is a dict {"seq", "event", "prev", "signature"}. ``prev`` is the SHA‑256 of the
previous entry's signed bytes (64 zeros for the first entry). The signature covers
``seq``, ``event`` and ``prev``, so entries cannot be edited, removed or reordered
without detection.

The implementation now uses the post‑quantum signature scheme **ML‑DSA‑65** from
`liboqs` instead of classical ECDSA.  The public API (`generate_keypair`,
`AuditLog.append`, `verify_log`) is unchanged, so existing tests continue to work.
"""

import base64
import hashlib
import json

import oqs
from cryptography.exceptions import InvalidSignature  # kept for compatibility


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #
def generate_keypair():
    """
    Return ``(public_key, private_key)`` as raw bytes for the log writer.

    The keys are generated with the post‑quantum signature scheme **ML‑DSA‑65**.
    """
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()          # bytes
    private_key = sig.export_secret_key()        # bytes
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Helper functions for entry handling
# --------------------------------------------------------------------------- #
def _entry_bytes(seq, event, prev):
    """Canonical JSON representation of an entry (without the signature)."""
    return json.dumps(
        {"seq": seq, "event": event, "prev": prev},
        sort_keys=True,
        separators=(",", ":")  # compact, deterministic
    ).encode()


def _sign(private_key, data):
    """
    Sign *data* with the supplied private key (raw bytes) using ML‑DSA‑65.

    Returns the raw signature bytes.
    """
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    return signer.sign(data)


def _verify(public_key, data, signature):
    """
    Verify a signature created by :func:`_sign`.

    Returns ``True`` if the signature is valid, ``False`` otherwise.
    """
    verifier = oqs.Signature("ML-DSA-65")
    try:
        return verifier.verify(data, signature, public_key)
    except (InvalidSignature, ValueError):
        # ``InvalidSignature`` is from ``cryptography`` and is kept for backward
        # compatibility; ``ValueError`` can be raised by liboqs for malformed inputs.
        return False


# --------------------------------------------------------------------------- #
# Audit log implementation
# --------------------------------------------------------------------------- #
GENESIS = "0" * 64  # 64 hex chars = 32 zero bytes expressed as hex


class AuditLog:
    """
    Append‑only log writer.

    ``entries`` can be stored and later checked with :func:`verify_log`.
    """

    def __init__(self, private_key):
        """
        Initialise the log with a private key (raw bytes as returned by
        :func:`generate_keypair`).
        """
        self._private_key = private_key
        self.entries = []
        self._prev = GENESIS

    def append(self, event):
        """
        Append a new *event* to the log.

        Returns the newly created entry dictionary, which contains the base64‑encoded
        signature.
        """
        seq = len(self.entries)
        data = _entry_bytes(seq, event, self._prev)

        signature_raw = _sign(self._private_key, data)
        entry = {
            "seq": seq,
            "event": event,
            "prev": self._prev,
            "signature": base64.b64encode(signature_raw).decode(),
        }

        self.entries.append(entry)
        # Update the hash chain for the next entry.
        self._prev = hashlib.sha256(data).hexdigest()
        return entry


def verify_log(public_key, entries):
    """
    Verify the whole chain.

    ``public_key`` must be the raw public key bytes produced by
    :func:`generate_keypair`.  ``entries`` is the list of entry dictionaries
    (as produced by :class:`AuditLog`).

    Returns ``True`` if the chain is intact and every signature is valid,
    otherwise ``False``.
    """
    prev = GENESIS
    for i, entry in enumerate(entries):
        try:
            data = _entry_bytes(entry["seq"], entry["event"], entry["prev"])
            signature = base64.b64decode(entry["signature"])
        except (KeyError, ValueError, TypeError):
            return False

        if entry["seq"] != i:
            return False
        if entry["prev"] != prev:
            return False
        if not _verify(public_key, data, signature):
            return False

        prev = hashlib.sha256(data).hexdigest()
    return True
