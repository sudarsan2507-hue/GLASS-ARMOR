"""Post‑quantum TLS‑like handshake using liboqs (ML‑KEM‑768).

The client offers suites (one key‑share per suite); the server picks the first suite
in its preference list that the client offers, answers with its own key‑share, and both
sides derive the session key with HKDF‑SHA256 bound to the suite and both hello messages.
Records are encrypted with AES‑256‑GCM and a random nonce per record.

Public API (unchanged):
    state, hello = client_hello()                 # offers CLIENT_SUITES by default
    server_key, suite, reply = server_hello(hello)
    client_key = client_finish(state, reply)

    ch = Channel(server_key)          # or Channel(client_key)
    enc = ch.seal(b"data")
    dec = ch.open(enc)
"""

import base64
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
#  Cipher‑suite configuration – only post‑quantum suites are offered/accepted. #
# --------------------------------------------------------------------------- #
# Whitelist of suites that are considered post‑quantum safe.
PQ_SUITES = {"ML-KEM-768-AES256GCM"}

# Server preference list – ordered by security, only PQ suites.
SERVER_PREFERENCE = ["ML-KEM-768-AES256GCM"]

# Default client offer – only PQ suites.
CLIENT_SUITES = ["ML-KEM-768-AES256GCM"]


# --------------------------------------------------------------------------- #
#  ML‑KEM‑768 key‑exchange wrapper                                            #
# --------------------------------------------------------------------------- #
class _MLKEM:
    """Key‑exchange implementation based on liboqs ML‑KEM‑768.

    * ``keypair`` returns a tuple ``(secret_key_bytes, public_key_bytes)``.
    * ``respond`` (server side) receives the client’s public key, encapsulates a
      shared secret and returns ``(shared_secret, ciphertext)`` where the ciphertext
      is the server’s key‑share.
    * ``finish`` (client side) receives the client’s secret key and the server’s
      ciphertext and decapsulates the same shared secret.
    """

    _alg = "ML-KEM-768"

    def keypair(self):
        kem = oqs.KeyEncapsulation(self._alg)
        public_key = kem.generate_keypair()          # bytes
        secret_key = kem.export_secret_key()         # bytes
        # ``kem`` object is not needed after generation; we keep only the raw keys.
        return secret_key, public_key

    def respond(self, client_share: bytes):
        """Server side: encapsulate using the client’s public key."""
        kem = oqs.KeyEncapsulation(self._alg)
        ciphertext, shared_secret = kem.encap_secret(client_share)
        return shared_secret, ciphertext

    def finish(self, secret_key: bytes, server_share: bytes):
        """Client side: decapsulate using own secret key."""
        kem = oqs.KeyEncapsulation(self._alg, secret_key=secret_key)
        shared_secret = kem.decap_secret(server_share)
        return shared_secret


# --------------------------------------------------------------------------- #
#  Suite → KEX mapping                                                         #
# --------------------------------------------------------------------------- #
KEX = {"ML-KEM-768-AES256GCM": _MLKEM()}


# --------------------------------------------------------------------------- #
#  Session‑key derivation (HKDF‑SHA256)                                         #
# --------------------------------------------------------------------------- #
def _session_key(shared_secret: bytes, suite: str, hello: bytes, reply: bytes) -> bytes:
    info = b"pq-gate suites v1|" + suite.encode() + b"|" + hello + b"|" + reply
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
#  Handshake helpers                                                            #
# --------------------------------------------------------------------------- #
def _filter_to_pq(suites):
    """Return only suites that are in the post‑quantum whitelist."""
    return [s for s in suites if s in PQ_SUITES]


def _ensure_all_pq(suites):
    """Validate that every suite in *suites* is post‑quantum.

    Raises:
        ValueError: If a non‑PQ suite is present.
    """
    non_pq = [s for s in suites if s not in PQ_SUITES]
    if non_pq:
        raise ValueError(f"non‑post‑quantum suites offered or used: {non_pq}")


def client_hello(offered=None):
    """Return ``(state, hello_bytes)``.

    ``state`` holds the raw secret keys needed later by ``client_finish``.
    ``hello_bytes`` is a JSON document containing the offered suites and the
    base64‑encoded public shares.

    The function validates that *offered* contains only post‑quantum suites.
    """
    # Resolve the offered list (defaulting to CLIENT_SUITES) and enforce PQ only.
    offered_raw = list(offered or CLIENT_SUITES)
    _ensure_all_pq(offered_raw)

    # Keep only suites that we actually support (i.e. are in PQ_SUITES).
    offered = _filter_to_pq(offered_raw)

    secrets_, shares = {}, {}
    for suite in offered:
        secret_key, public_key = KEX[suite].keypair()
        secrets_[suite] = secret_key
        shares[suite] = base64.b64encode(public_key).decode()
    hello = json.dumps({"suites": offered, "shares": shares}).encode()
    return {"secrets": secrets_, "hello": hello}, hello


def server_hello(hello: bytes):
    """Return ``(session_key, chosen_suite, reply_bytes)``.

    Raises ``ValueError`` if no common post‑quantum suite is found.
    """
    msg = json.loads(hello)

    # Ensure the client did not sneak in any non‑PQ suite.
    client_suites = msg.get("suites", [])
    _ensure_all_pq(client_suites)

    # Restrict selection to suites that are both in the server preference,
    # advertised by the client, and recognised as post‑quantum.
    suite = next(
        (
            s
            for s in SERVER_PREFERENCE
            if s in client_suites
            and s in msg.get("shares", {})
            and s in PQ_SUITES
        ),
        None,
    )
    if suite is None:
        raise ValueError("no common post‑quantum cipher suite")

    client_share = base64.b64decode(msg["shares"][suite])
    shared, server_share = KEX[suite].respond(client_share)

    reply = json.dumps(
        {"suite": suite, "share": base64.b64encode(server_share).decode()}
    ).encode()
    return _session_key(shared, suite, hello, reply), suite, reply


def client_finish(state: dict, reply: bytes) -> bytes:
    """Return the client’s view of the session key."""
    msg = json.loads(reply)
    suite = msg["suite"]
    if suite not in state["secrets"]:
        raise ValueError("server chose a suite we did not offer")
    if suite not in PQ_SUITES:
        # Defensive check – should never happen because client_hello filters.
        raise ValueError("chosen suite is not post‑quantum")
    server_share = base64.b64decode(msg["share"])
    shared = KEX[suite].finish(state["secrets"][suite], server_share)
    return _session_key(shared, suite, state["hello"], reply)


# --------------------------------------------------------------------------- #
#  Secure channel (AES‑256‑GCM)                                                #
# --------------------------------------------------------------------------- #
class Channel:
    """Encrypt/decrypt records with AES‑256‑GCM under the derived session key."""

    def __init__(self, session_key: bytes):
        self._aead = AESGCM(session_key)

    def seal(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` and prepend a fresh 12‑byte nonce."""
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, None)

    def open(self, record: bytes) -> bytes:
        """Decrypt a record produced by :meth:`seal`."""
        nonce, ciphertext = record[:12], record[12:]
        return self._aead.decrypt(nonce, ciphertext, None)
