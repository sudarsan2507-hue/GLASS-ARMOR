"""Minimal TLS-like handshake with cipher-suite negotiation.
Post-quantum version: the only suite is hybrid X25519 + ML-KEM-768 (no classical suites).

The client offers suites (with one key share per suite); the server picks the first suite
in ITS preference list that the client offers, answers with its own key share, and both
sides derive the session key with HKDF-SHA256 over both shared secrets, bound to the suite
and both hello messages. Channel then encrypts records with AES-256-GCM and a random nonce.

    state, hello = client_hello()                 # offers CLIENT_SUITES by default
    server_key, suite, reply = server_hello(hello)
    client_key = client_finish(state, reply)
client share = X25519 public (32) | ML-KEM public (1184)
server share = X25519 public (32) | ML-KEM ciphertext (1088)
"""
import base64
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SERVER_PREFERENCE = ["X25519MLKEM768-AES256GCM"]
CLIENT_SUITES = ["X25519MLKEM768-AES256GCM"]
_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class _X25519MLKEM768:
    _kem = "ML-KEM-768"

    def keypair(self):
        x_sk = X25519PrivateKey.generate()
        with oqs.KeyEncapsulation(self._kem) as kem:
            kem_pk, kem_sk = kem.generate_keypair(), kem.export_secret_key()
        return (x_sk, kem_sk), x_sk.public_key().public_bytes(*_RAW) + kem_pk

    def respond(self, client_share):
        if len(client_share) != 32 + 1184:
            raise ValueError("bad key share")
        x_sk = X25519PrivateKey.generate()
        classical = x_sk.exchange(X25519PublicKey.from_public_bytes(client_share[:32]))
        with oqs.KeyEncapsulation(self._kem) as kem:
            kem_ct, pq = kem.encap_secret(client_share[32:])
        return classical + classical, x_sk.public_key().public_bytes(*_RAW) + kem_ct

    def finish(self, sk, server_share):
        if len(server_share) != 32 + 1088:
            raise ValueError("bad key share")
        x_sk, kem_sk = sk
        classical = x_sk.exchange(X25519PublicKey.from_public_bytes(server_share[:32]))
        with oqs.KeyEncapsulation(self._kem, secret_key=kem_sk) as kem:
            pq = kem.decap_secret(server_share[32:])
        return classical + classical


KEX = {"X25519MLKEM768-AES256GCM": _X25519MLKEM768()}


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
    shared = KEX[suite].finish(state["secrets"][suite], base64.b64decode(msg["share"]))
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
