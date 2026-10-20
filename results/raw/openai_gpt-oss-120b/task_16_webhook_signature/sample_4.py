"""Signed webhooks (ML‑DSA‑65), Stripe‑style signature header.

The sender signs "<timestamp>.<body>" and sends the header
    X-Signature: t=<unix time>,v1=<base64 signature>
The receiver keeps one public key per signature scheme (dict scheme -> key), checks the
signature for its scheme and rejects messages older than `tolerance` seconds (replay window).

This implementation replaces the original ECDSA‑P256 scheme with the post‑quantum
ML‑DSA‑65 signature algorithm from liboqs, while preserving the public API
(`generate_keypair`, `sign_webhook`, `verify_webhook`) so existing tests continue to pass.
"""

import base64
import time

import oqs  # liboqs‑python

SCHEME = "v1"


def generate_keypair():
    """Return (public_key, private_key) as raw bytes for the webhook sender.

    The keys are generated with the ML‑DSA‑65 algorithm.  They are returned as the
    raw byte strings produced by liboqs; they are suitable for direct use with the
    other functions in this module.
    """
    signer = oqs.Signature("ML-DSA-65")
    public_key = signer.generate_keypair()          # bytes
    private_key = signer.export_secret_key()        # bytes
    return public_key, private_key


def sign_webhook(private_key, body, timestamp=None):
    """Return the X‑Signature header value for `body` (bytes).

    The message that is signed is ``"<timestamp>.<body>"`` where the timestamp
    is an integer Unix epoch value.  The resulting signature is base64‑encoded
    and placed in the header together with the timestamp.
    """
    ts = int(time.time() if timestamp is None else timestamp)
    signer = oqs.Signature("ML-DSA-65", secret_key=private_key)
    message = str(ts).encode() + b"." + body
    signature = signer.sign(message)                # bytes
    b64_sig = base64.b64encode(signature).decode()
    return f"t={ts},{SCHEME}={b64_sig}"


def _parse(header):
    """Parse a Stripe‑style signature header into a dict of fields."""
    fields = {}
    for part in header.split(","):
        name, _, value = part.partition("=")
        fields[name.strip()] = value.strip()
    return fields


def verify_webhook(keys, body, header, now=None, tolerance=300):
    """Validate a webhook signature.

    * ``keys`` – mapping ``{scheme: public_key_bytes}``.  Only the entry for
      ``SCHEME`` (``"v1"``) is consulted.
    * ``body`` – raw request body (bytes).
    * ``header`` – the value of the ``X‑Signature`` header.
    * ``now`` – optional current time (float).  If omitted, ``time.time()`` is used.
    * ``tolerance`` – maximum age of a request in seconds (default 5 minutes).

    Returns ``True`` if the signature is valid and the timestamp is within the
    allowed window; otherwise ``False``.
    """
    try:
        fields = _parse(header)
        ts = int(fields["t"])
        signature = base64.b64decode(fields[SCHEME])
        public_key = keys[SCHEME]

        verifier = oqs.Signature("ML-DSA-65")
        message = str(ts).encode() + b"." + body
        if not verifier.verify(message, signature, public_key):
            return False
    except (KeyError, ValueError, Exception):
        # ``Exception`` catches liboqs‑specific errors (e.g. malformed keys)
        return False

    now = time.time() if now is None else now
    return abs(now - ts) <= tolerance
