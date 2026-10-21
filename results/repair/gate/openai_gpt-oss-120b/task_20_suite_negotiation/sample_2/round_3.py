"""Post‑quantum TLS‑like handshake (ML‑KEM‑768 / AES‑256‑GCM).

The public API (client_hello, server_hello, client_finish, Channel) is unchanged,
so existing tests continue to work. Internally the classic EC key‑exchange is
replaced by a ML‑KEM‑768 key‑encapsulation mechanism from liboqs. The session key
derivation and record protection remain the same (HKDF‑SHA256 + AES‑256‑GCM).

Only post‑quantum cipher suites are ever offered, accepted, or preferred.
Any classical suite that appears in a client’s offer is silently ignored, and
the server will never select a suite that is not explicitly listed in the
post‑quantum whitelist. This eliminates the risk that a classical algorithm is
accepted or preferred.
"""

import base64
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Cipher‑suite configuration
# --------------------------------------------------------------------------- #
# Server prefers only post‑quantum suites.
SERVER_PREFERENCE = ["ML-KEM-768-AES256GCM"]
# Client offers only post‑quantum suites by default.
CLIENT_SUITES = ["ML-KEM-768-AES256GCM"]

# --------------------------------------------------------------------------- #
# Post‑quantum KEM wrapper
# --------------------------------------------------------------------------- #
class _MLKEM:
    """Wrap liboqs ML‑KEM‑768 to present the same interface as the old EC classes.

    * ``keypair`` returns a tuple ``(kem_obj, public_key_bytes)`` where ``kem_obj``
      holds the secret key and can later be used for decapsulation.
    * ``respond`` receives the client’s public key, encapsulates a secret and
      returns ``(shared_secret, ciphertext)``.
    * ``finish`` decapsulates the ciphertext using the stored ``kem_obj``.
    """

    _ALG = "ML-KEM-768"

    def keypair(self):
        """Generate a KEM key‑pair.

        Returns
        -------
        (kem_obj, public_key_bytes)
            * ``kem_obj`` – an ``oqs.KeyEncapsulation`` instance that holds the
              secret key (used later for decapsulation).
            * ``public_key_bytes`` – the public key that is sent to the peer.
        """
        kem = oqs.KeyEncapsulation(self._ALG)
        public_key = kem.generate_keypair()          # bytes
        # ``kem`` now contains the secret key internally; we keep the object.
        return kem, public_key

    def respond(self, client_share):
        """Encapsulate a secret for the client.

        Parameters
        ----------
        client_share : bytes
            The client’s public key.

        Returns
        -------
        (shared_secret, ciphertext)
            * ``shared_secret`` – the 32‑byte secret that both sides will derive.
            * ``ciphertext`` – the encapsulated value that the client will decapsulate.
        """
        kem = oqs.KeyEncapsulation(self._ALG)
        ciphertext, shared_secret = kem.encap_secret(client_share)
        return shared_secret, ciphertext

    def finish(self, kem_obj, server_share):
        """Decapsulate the server’s ciphertext.

        Parameters
        ----------
        kem_obj : oqs.KeyEncapsulation
            The object returned by ``keypair`` (holds the secret key).
        server_share : bytes
            The ciphertext received from the server.

        Returns
        -------
        bytes
            The shared secret (32 bytes).
        """
        return kem_obj.decap_secret(server_share)


# Mapping from suite name to the implementation object.
KEX = {"ML-KEM-768-AES256GCM": _MLKEM()}

# Explicit whitelist of post‑quantum suites we are willing to use.
# This is used to guarantee that no classical suite is ever accepted.
POST_QUANTUM_SUITES = set(KEX.keys())

# --------------------------------------------------------------------------- #
# Helper: derive the session key from the shared secret and transcript.
# --------------------------------------------------------------------------- #
def _session_key(shared_secret, suite, hello, reply):
    """Derive a 32‑byte session key with HKDF‑SHA256.

    The ``info`` field binds the suite name and the two hello messages to the
    derived key, mimicking TLS 1.3’s transcript‑hash binding.
    """
    info = b"pq-gate suites v1|" + suite.encode() + b"|" + hello + b"|" + reply
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
# Handshake primitives (public API)
# --------------------------------------------------------------------------- #
def client_hello(offered=None):
    """Create a client hello.

    Only post‑quantum suites that are actually implemented are offered.
    Classical suites are silently ignored to avoid accidental acceptance.

    Parameters
    ----------
    offered : iterable of str, optional
        Caller‑provided list of suites. If omitted, ``CLIENT_SUITES`` is used.
        Any suite not in :data:`POST_QUANTUM_SUITES` is discarded.

    Returns
    -------
    (state, hello_bytes)
        * ``state`` – a dict that stores the private KEM objects and the raw hello.
        * ``hello_bytes`` – JSON‑encoded message sent to the server.
    """
    # Use the caller‑provided list if present, otherwise fall back to the default.
    offered = list(offered) if offered is not None else CLIENT_SUITES

    # Keep only suites we have a post‑quantum implementation for.
    supported = [s for s in offered if s in POST_QUANTUM_SUITES]
    if not supported:
        raise ValueError("No supported post‑quantum cipher suite offered by client")

    secrets_, shares = {}, {}
    for suite in supported:
        kem_obj, share = KEX[suite].keypair()
        secrets_[suite] = kem_obj
        shares[suite] = base64.b64encode(share).decode()

    hello = json.dumps({"suites": supported, "shares": shares}).encode()
    return {"secrets": secrets_, "hello": hello}, hello


def server_hello(hello):
    """Process a client hello and produce a server hello.

    Returns
    -------
    (session_key, chosen_suite, reply_bytes)

    Raises
    ------
    ValueError
        If no mutually supported suite is found.
    """
    msg = json.loads(hello)

    # Choose the first suite that is both in the server's preference list,
    # offered by the client, and in our post‑quantum whitelist.
    suite = next(
        (
            s
            for s in SERVER_PREFERENCE
            if s in msg["suites"] and s in msg["shares"] and s in POST_QUANTUM_SUITES
        ),
        None,
    )
    if suite is None:
        raise ValueError("no common post‑quantum cipher suite")

    client_share = base64.b64decode(msg["shares"][suite])
    shared, ciphertext = KEX[suite].respond(client_share)

    reply = json.dumps(
        {"suite": suite, "share": base64.b64encode(ciphertext).decode()}
    ).encode()
    return _session_key(shared, suite, hello, reply), suite, reply


def client_finish(state, reply):
    """Complete the handshake on the client side.

    Returns
    -------
    session_key : bytes
        The 32‑byte key derived from the shared secret.
    """
    msg = json.loads(reply)
    suite = msg["suite"]
    if suite not in state["secrets"]:
        raise ValueError("server chose a suite we did not offer")
    if suite not in POST_QUANTUM_SUITES:
        # Defensive check – should never happen because the server enforces it.
        raise ValueError("selected suite is not post‑quantum")
    server_share = base64.b64decode(msg["share"])
    shared = KEX[suite].finish(state["secrets"][suite], server_share)
    return _session_key(shared, suite, state["hello"], reply)


# --------------------------------------------------------------------------- #
# Secure channel (unchanged – still AES‑256‑GCM)
# --------------------------------------------------------------------------- #
class Channel:
    """Encrypt/decrypt records with AES‑256‑GCM using the derived session key."""

    def __init__(self, session_key):
        self._aead = AESGCM(session_key)

    def seal(self, plaintext):
        """Encrypt ``plaintext`` and prepend a random 12‑byte nonce."""
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, None)

    def open(self, record):
        """Decrypt a record produced by :meth:`seal`."""
        return self._aead.decrypt(record[:12], record[12:], None)
