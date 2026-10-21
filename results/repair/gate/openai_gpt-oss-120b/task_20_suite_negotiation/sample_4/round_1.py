"""Minimal TLS‑like handshake using a post‑quantum KEM (ML‑KEM‑768).

The client offers suites (each with one key share). The server picks the first
suite in its preference list that the client offers, answers with its own key
share, and both sides derive the session key with HKDF‑SHA256 bound to the suite
and both hello messages. Records are encrypted with AES‑256‑GCM and a random
nonce per record.

Public API (unchanged):
    state, hello = client_hello()                 # offers CLIENT_SUITES by default
    server_key, suite, reply = server_hello(hello)
    client_key = client_finish(state, reply)

Hellos are JSON bytes; key shares are base64‑encoded.
"""

import base64
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
#  Preference / offering lists – now using a post‑quantum KEM                #
# --------------------------------------------------------------------------- #
SERVER_PREFERENCE = ["ML-KEM-768-AES256GCM"]
CLIENT_SUITES = ["ML-KEM-768-AES256GCM"]

# --------------------------------------------------------------------------- #
#  Post‑quantum KEM wrapper matching the old KEX interface                    #
# --------------------------------------------------------------------------- #
class _MLKEM:
    """Key‑exchange wrapper for ML‑KEM‑768.

    * ``keypair`` returns (secret_key_bytes, public_key_bytes).
    * ``respond`` (server side) takes the client public key and returns
      (shared_secret, ciphertext) where the ciphertext is sent back as the
      server's key share.
    * ``finish`` (client side) decapsulates the server ciphertext using the
      stored secret key and returns the shared secret.
    """

    _ALG = "ML-KEM-768"

    def keypair(self):
        """Generate a fresh key‑pair.

        Returns
        -------
        secret_key : bytes
            Private key material (to be stored by the client).
        public_key : bytes
            Public key that will be sent to the server (base64‑encoded later).
        """
        kem = oqs.KeyEncapsulation(self._ALG)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return secret_key, public_key

    def respond(self, client_share):
        """Server side: encapsulate a secret for the client.

        Parameters
        ----------
        client_share : bytes
            The client's public key.

        Returns
        -------
        shared_secret : bytes
            The secret that both parties will derive.
        ciphertext : bytes
            The encapsulated ciphertext that is sent back as the server's share.
        """
        kem = oqs.KeyEncapsulation(self._ALG)
        ciphertext, shared_secret = kem.encap_secret(client_share)
        return shared_secret, ciphertext

    def finish(self, secret_key, server_share):
        """Client side: decapsulate the server's ciphertext.

        Parameters
        ----------
        secret_key : bytes
            The client's private key (as returned by ``keypair``).
        server_share : bytes
            The ciphertext received from the server.

        Returns
        -------
        shared_secret : bytes
            The secret that both parties will derive.
        """
        kem = oqs.KeyEncapsulation(self._ALG, secret_key=secret_key)
        shared_secret = kem.decap_secret(server_share)
        return shared_secret


# Mapping from suite name to its KEX implementation
KEX = {"ML-KEM-768-AES256GCM": _MLKEM()}

# Set of suites we actually support (post‑quantum only)
_SUPPORTED_SUITES = set(KEX.keys())

# --------------------------------------------------------------------------- #
#  Session‑key derivation (unchanged)                                         #
# --------------------------------------------------------------------------- #
def _session_key(shared_secret, suite, hello, reply):
    """Derive a 32‑byte session key from the shared secret and transcript."""
    info = b"pq-gate suites v1|" + suite.encode() + b"|" + hello + b"|" + reply
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
#  Handshake helpers (public API)                                            #
# --------------------------------------------------------------------------- #
def client_hello(offered=None):
    """Create a client hello.

    The function filters the offered suites to those we actually support.
    If after filtering no suite remains, a ``ValueError`` is raised.

    Returns
    -------
    state : dict
        Contains the generated secret keys and the raw hello bytes.
    hello : bytes
        JSON‑encoded hello message to be sent to the server.
    """
    # Start from the caller‑provided list or the default client list
    offered = list(offered or CLIENT_SUITES)

    # Keep only suites we have a post‑quantum implementation for
    offered = [s for s in offered if s in _SUPPORTED_SUITES]

    if not offered:
        raise ValueError("no supported post‑quantum cipher suite offered")

    secrets_, shares = {}, {}
    for suite in offered:
        secret, share = KEX[suite].keypair()
        secrets_[suite] = secret
        shares[suite] = base64.b64encode(share).decode()
    hello = json.dumps({"suites": offered, "shares": shares}).encode()
    return {"secrets": secrets_, "hello": hello}, hello


def server_hello(hello):
    """Process a client hello and produce a server hello.

    Only suites present in :data:`SERVER_PREFERENCE` (which are all
    post‑quantum) are considered. If the client offered only unsupported
    (e.g., classical) suites, a ``ValueError`` is raised.

    Returns
    -------
    session_key : bytes
        The derived session key.
    suite : str
        The chosen cipher suite.
    reply : bytes
        JSON‑encoded server hello to be sent back to the client.

    Raises
    ------
    ValueError
        If no common suite can be negotiated.
    """
    msg = json.loads(hello)

    # Choose the first suite that we prefer and that the client actually offered
    suite = next(
        (s for s in SERVER_PREFERENCE if s in msg.get("suites", []) and s in msg.get("shares", {})),
        None,
    )
    if suite is None:
        raise ValueError("no common post‑quantum cipher suite")

    shared, share = KEX[suite].respond(base64.b64decode(msg["shares"][suite]))
    reply = json.dumps(
        {"suite": suite, "share": base64.b64encode(share).decode()}
    ).encode()
    return _session_key(shared, suite, hello, reply), suite, reply


def client_finish(state, reply):
    """Complete the handshake on the client side.

    Returns
    -------
    session_key : bytes
        The derived session key.
    """
    msg = json.loads(reply)
    suite = msg["suite"]
    if suite not in state["secrets"]:
        raise ValueError("server chose a suite we did not offer")
    shared = KEX[suite].finish(
        state["secrets"][suite], base64.b64decode(msg["share"])
    )
    return _session_key(shared, suite, state["hello"], reply)


# --------------------------------------------------------------------------- #
#  Secure channel (unchanged)                                                #
# --------------------------------------------------------------------------- #
class Channel:
    """Encrypt / decrypt records with AES‑256‑GCM under the session key."""

    def __init__(self, session_key):
        self._aead = AESGCM(session_key)

    def seal(self, plaintext):
        """Encrypt ``plaintext`` and prepend the nonce."""
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, None)

    def open(self, record):
        """Decrypt a record produced by :meth:`seal`."""
        return self._aead.decrypt(record[:12], record[12:], None)
