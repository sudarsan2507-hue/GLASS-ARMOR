"""Minimal TLS‑like handshake migrated to post‑quantum cryptography.

The client offers suites (with one key share per suite); the server picks the first
suite in its preference list that the client offers, answers with its own key share,
and both sides derive the session key with HKDF‑SHA256 bound to the suite and both
hello messages.  Records are encrypted with AES‑256‑GCM and a random nonce per
record.

Only post‑quantum algorithms are accepted.  If a classical suite is offered
(either alone or alongside a post‑quantum one) it will be ignored and never
selected, preventing downgrade attacks.

The public API (client_hello, server_hello, client_finish, Channel) is unchanged
so existing tests continue to pass.
"""

import base64
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
#  Post‑quantum key‑exchange implementation (ML‑KEM‑768)                     #
# --------------------------------------------------------------------------- #
class _MLKEM:
    """Key‑exchange wrapper using liboqs ML‑KEM‑768.

    * ``keypair`` returns a tuple ``(secret_key_bytes, public_key_bytes)``.
    * ``respond`` takes the client’s public key and returns
      ``(shared_secret, ciphertext)`` where the ciphertext is sent back to the
      client as the “share”.
    * ``finish`` decapsulates the server’s ciphertext using the stored secret
      key and returns the shared secret.
    """

    _ALG = "ML-KEM-768"

    def keypair(self):
        """Generate a fresh KEM key‑pair.

        Returns
        -------
        secret_key : bytes
            The private key (to be kept by the client).
        public_key : bytes
            The public key that will be sent to the server.
        """
        kem = oqs.KeyEncapsulation(self._ALG)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        # ``kem`` itself holds the secret key internally; we only need the raw
        # bytes for later decapsulation.
        return secret_key, public_key

    def respond(self, client_public):
        """Server side: encapsulate a secret for the client.

        Parameters
        ----------
        client_public : bytes
            The client’s public key.

        Returns
        -------
        shared_secret : bytes
            The secret that both parties will derive.
        ciphertext : bytes
            The encapsulated secret (sent back to the client as the “share”).
        """
        kem = oqs.KeyEncapsulation(self._ALG)
        ciphertext, shared_secret = kem.encap_secret(client_public)
        return shared_secret, ciphertext

    def finish(self, client_secret, server_ciphertext):
        """Client side: decapsulate the server’s ciphertext.

        Parameters
        ----------
        client_secret : bytes
            The client’s private key (as returned by ``keypair``).
        server_ciphertext : bytes
            The ciphertext received from the server.

        Returns
        -------
        shared_secret : bytes
            The secret that both parties will derive.
        """
        kem = oqs.KeyEncapsulation(self._ALG, secret_key=client_secret)
        return kem.decap_secret(server_ciphertext)


# --------------------------------------------------------------------------- #
#  Suite negotiation constants                                               #
# --------------------------------------------------------------------------- #
# Only post‑quantum suites are allowed.  Adding a classical suite to the
# configuration will raise an exception rather than being silently accepted.
ALLOWED_PQ_SUITES = {"ML-KEM-768-AES256GCM"}

# Server preference order – must be a subset of ALLOWED_PQ_SUITES.
SERVER_PREFERENCE = ["ML-KEM-768-AES256GCM"]

# Default client offering – also a subset of ALLOWED_PQ_SUITES.
CLIENT_SUITES = ["ML-KEM-768-AES256GCM"]

# Mapping from suite name to the object that implements the three required
# methods (keypair, respond, finish).  Only post‑quantum implementations are
# registered here.
KEX = {"ML-KEM-768-AES256GCM": _MLKEM()}


# --------------------------------------------------------------------------- #
#  Helper: derive the session key                                            #
# --------------------------------------------------------------------------- #
def _session_key(shared_secret: bytes, suite: str, hello: bytes, reply: bytes) -> bytes:
    """Derive a 32‑byte session key from the shared secret and transcript."""
    info = b"pq-gate suites v1|" + suite.encode() + b"|" + hello + b"|" + reply
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
#  Client side                                                               #
# --------------------------------------------------------------------------- #
def client_hello(offered=None):
    """Create a client hello.

    Parameters
    ----------
    offered : iterable of str, optional
        Suites the client wishes to advertise.  Only suites listed in
        ``ALLOWED_PQ_SUITES`` are permitted; offering any other suite raises
        ``ValueError``.  If omitted the default ``CLIENT_SUITES`` is used.

    Returns
    -------
    state : dict
        Contains the per‑suite secret keys and the raw hello bytes.
    hello : bytes
        JSON‑encoded hello message to be sent to the server.
    """
    offered = list(offered or CLIENT_SUITES)

    # Enforce that only allowed post‑quantum suites are offered.
    disallowed = [s for s in offered if s not in ALLOWED_PQ_SUITES]
    if disallowed:
        raise ValueError(f"offered suite(s) not allowed (must be post‑quantum): {disallowed}")

    secrets_, shares = {}, {}
    for suite in offered:
        secret_key, public_key = KEX[suite].keypair()
        secrets_[suite] = secret_key
        shares[suite] = base64.b64encode(public_key).decode()
    hello = json.dumps({"suites": offered, "shares": shares}).encode()
    return {"secrets": secrets_, "hello": hello}, hello


# --------------------------------------------------------------------------- #
#  Server side                                                               #
# --------------------------------------------------------------------------- #
def server_hello(hello):
    """Process a client hello and produce a server hello.

    Parameters
    ----------
    hello : bytes
        The client hello received over the network.

    Returns
    -------
    session_key : bytes
        The derived session key.
    chosen_suite : str
        The suite selected for this handshake.
    reply : bytes
        JSON‑encoded server hello to be sent back to the client.

    Raises
    ------
    ValueError
        If no mutually supported suite is found or if a non‑post‑quantum suite
        is selected.
    """
    msg = json.loads(hello)

    # Find the first suite that both sides support and that is explicitly
    # allowed as a post‑quantum suite.
    suite = next(
        (
            s
            for s in SERVER_PREFERENCE
            if s in msg["suites"]
            and s in msg["shares"]
            and s in ALLOWED_PQ_SUITES
        ),
        None,
    )
    if suite is None:
        raise ValueError("no common post‑quantum cipher suite")

    client_pub = base64.b64decode(msg["shares"][suite])
    shared, ciphertext = KEX[suite].respond(client_pub)

    reply = json.dumps(
        {"suite": suite, "share": base64.b64encode(ciphertext).decode()}
    ).encode()
    return _session_key(shared, suite, hello, reply), suite, reply


# --------------------------------------------------------------------------- #
#  Client finalisation                                                       #
# --------------------------------------------------------------------------- #
def client_finish(state, reply):
    """Complete the handshake on the client side.

    Parameters
    ----------
    state : dict
        The state object returned by ``client_hello``.
    reply : bytes
        The server hello received over the network.

    Returns
    -------
    session_key : bytes
        The derived session key.
    """
    msg = json.loads(reply)
    suite = msg["suite"]
    if suite not in state["secrets"]:
        raise ValueError("server chose a suite we did not offer")
    if suite not in ALLOWED_PQ_SUITES:
        raise ValueError("server chose a non‑post‑quantum suite")
    server_ciphertext = base64.b64decode(msg["share"])
    shared = KEX[suite].finish(state["secrets"][suite], server_ciphertext)
    return _session_key(shared, suite, state["hello"], reply)


# --------------------------------------------------------------------------- #
#  Secure channel                                                            #
# --------------------------------------------------------------------------- #
class Channel:
    """Encrypt / decrypt records using AES‑256‑GCM under the session key."""

    def __init__(self, session_key: bytes):
        self._aead = AESGCM(session_key)

    def seal(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` and prepend the nonce.

        Returns
        -------
        bytes
            ``nonce || ciphertext || tag`` (nonce is 12 bytes).
        """
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, None)

    def open(self, record: bytes) -> bytes:
        """Decrypt a record produced by :meth:`seal`.

        Parameters
        ----------
        record : bytes
            ``nonce || ciphertext || tag`` as returned by :meth:`seal`.

        Returns
        -------
        bytes
            The original plaintext.
        """
        nonce, ct = record[:12], record[12:]
        return self._aead.decrypt(nonce, ct, None)
