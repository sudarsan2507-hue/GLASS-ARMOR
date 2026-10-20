"""Minimal TLS-like handshake with cipher-suite negotiation.

The client offers suites (with one key share per suite); the server picks the first suite
in ITS preference list that the client offers, answers with its own key share, and both
sides derive the session key with HKDF-SHA256 bound to the suite and both hello messages.
Channel then encrypts records with AES-256-GCM and a random nonce per record.

    state, hello = client_hello()                 # offers CLIENT_SUITES by default
    server_key, suite, reply = server_hello(hello)
    client_key = client_finish(state, reply)
Hellos are JSON bytes; key shares are base64.
"""
import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import oqs

SERVER_PREFERENCE = ["ML-KEM-768-AES256GCM", "ML-KEM-65-AES256GCM"]
CLIENT_SUITES = ["ML-KEM-768-AES256GCM", "ML-KEM-65-AES256GCM"]


class _ML_KEM:
    def __init__(self, suite):
        self.kem = oqs.KeyEncapsulation(suite)
        self.kem.generate_keypair()
        self.public_key = self.kem.public_key
        self.secret_key = self.kem.export_secret_key()

    def respond(self, client_share):
        self.kem2 = oqs.KeyEncapsulation(self.kem.algorithm, secret_key=client_share)
        return self.kem2.encap_secret(self.public_key)

    def finish(self, client_share):
        self.kem2 = oqs.KeyEncapsulation(self.kem.algorithm, secret_key=client_share)
        return self.kem2.decap_secret(self.kem2.encap_secret(self.public_key))


KEX = {"ML-KEM-768-AES256GCM": _ML_KEM("ML-KEM-768"), "ML-KEM-65-AES256GCM": _ML_KEM("ML-KEM-65")}


def _session_key(shared_secret, suite, hello, reply):
    info = b"pq-gate suites v1|" + suite.encode() + b"|" + hello + b"|" + reply
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)


def client_hello(offered=None):
    """Returns (state, hello bytes)."""
    offered = list(offered or CLIENT_SUITES)
    secrets_, shares = {}, {}
    for suite in offered:
        secrets_[suite], share = KEX[suite].keypair()
        shares[suite] = base64.b64encode(share).decode()
    hello = json.dumps({"suites": offered, "shares": shares}).encode()
    return {"secrets": secrets_, "hello": hello}, hello


def server_hello(hello):
    """Returns (session_key, chosen_suite, reply bytes). Raises ValueError if nothing matches."""
    msg = json.loads(hello)
    suite = next((s for s in SERVER_PREFERENCE if s in msg["suites"] and s in msg["shares"]), None)
    if suite is None:
        raise ValueError("no common cipher suite")
    shared, share = KEX[suite].respond(base64.b64decode(msg["shares"][suite]))
    reply = json.dumps({"suite": suite, "share": base64.b64encode(share).decode()}).encode()
    return _session_key(shared, suite, hello, reply), suite, reply


def client_finish(state, reply):
    """Returns the client's session key."""
    msg = json.loads(reply)
    suite = msg["suite"]
    if suite not in state["secrets"]:
        raise ValueError("server chose a suite we did not offer")
    shared = KEX[suite].finish(base64.b64decode(msg["share"]))
    return _session_key(shared, suite, state["hello"], reply)


class Channel:
    """AES-256-GCM records under the session key."""

    def __init__(self, session_key):
        self._aead = AESGCM(session_key)

    def seal(self, plaintext):
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, None)

    def open(self, record):
        return self._aead.decrypt(record[:12], record[12:], None)
