"""Post‑quantum TLS‑like handshake.

The original implementation used classic elliptic‑curve key exchange
(X25519 / P‑256).  This version replaces the key‑exchange primitive with
the ML‑KEM‑768 algorithm from liboqs, keeping the public API
(`client_hello`, `server_hello`, `client_finish`, `Channel`) unchanged
so existing tests continue to work.

Each cipher suite is expressed as ``<KEM>-AES256GCM``.  The only
supported suite at the moment is ``ML-KEM-768-AES256GCM``.  The handshake
flow is:

    state, hello = client_hello()                 # offers CLIENT_SUITES
    session_key, suite, reply = server_hello(hello)
    client_key = client_finish(state, reply)

Both sides derive the same 32‑byte session key with HKDF‑SHA256 bound to
the suite name and the two hello messages.  Records are encrypted with
AES‑256‑GCM using a fresh 12‑byte nonce per record.

The implementation mirrors the original code structure:
* ``_MLKEM`` mimics the ``_X25519`` / ``_P256`` helpers but uses liboqs.
* ``KEX`` maps suite names to the appropriate helper object.
* ``_session_key`` and ``Channel`` are unchanged apart from imports.

Security note
-------------
Only post‑quantum KEM‑based suites are accepted.  If a client (or a
future server configuration) offers a classic algorithm, the handshake
fails with a clear error, eliminating the risk flagged by the security
checker (A2).
"""

import base64
import json
import os

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# Cipher‑suite preference lists
# --------------------------------------------------------------------------- #
SERVER_PREFERENCE = ["ML-KEM-768-AES256GCM"]
CLIENT_SUITES = ["ML-KEM-768-AES256GCM"]


# --------------------------------------------------------------------------- #
# Post‑quantum KEM helper
# --------------------------------------------------------------------------- #
class _MLKEM:
    """
    Helper that provides the same interface as the classic ``_X25519`` /
    ``_P256`` classes but uses the ML‑KEM‑768 key‑encapsulation mechanism.

    * ``keypair`` returns a tuple ``(secret_key_bytes, public_key_bytes)``.
      The secret key is stored by the client for later decapsulation.
    * ``respond`` receives the client’s public key, encapsulates a shared
      secret and returns ``(shared_secret, ciphertext)`` where the ciphertext
      is sent back to the client as the server’s “key share”.
    * ``finish`` decapsulates the server’s ciphertext using the stored secret
      key and returns the shared secret.
    """

    _kem_name = "ML-KEM-768"

    def keypair(self):
        """Generate a fresh KEM key‑pair.

        Returns
        -------
        secret_key : bytes
            Private key material (to be kept by the client).
        public_key : bytes
            Public key that is sent to the server (the “key share”).
        """
        kem = oqs.KeyEncapsulation(self._kem_name)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return secret_key, public_key

    def respond(self, client_share):
        """Encapsulate a shared secret for the client.

        Parameters
        ----------
        client_share : bytes
            The client’s public key.

        Returns
        -------
        shared_secret : bytes
            The secret that both sides will derive.
        ciphertext : bytes
            The encapsulated key (sent back to the client as the server’s
            key share).
        """
        kem = oqs.KeyEncapsulation(self._kem_name)
        ciphertext, shared_secret = kem.encap_secret(client_share)
        return shared_secret, ciphertext

    def finish(self, secret_key, server_share):
        """Decapsulate the server’s ciphertext.

        Parameters
        ----------
        secret_key : bytes
            The client’s private key (as returned by ``keypair``).
        server_share : bytes
            The ciphertext received from the server.

        Returns
        -------
        shared_secret : bytes
            The secret that both sides will derive.
        """
        kem = oqs.KeyEncapsulation(self._kem_name, secret_key=secret_key)
        return kem.decap_secret(server_share)


# Mapping from suite name to the helper implementing the KEX.
KEX = {"ML-KEM-768-AES256GCM": _MLKEM()}


# --------------------------------------------------------------------------- #
# Session‑key derivation (identical to the original implementation)
# --------------------------------------------------------------------------- #
def _session_key(shared_secret, suite, hello, reply):
    """
    Derive a 32‑byte session key from the raw shared secret.

    The HKDF input is bound to the suite name and both hello messages to
    provide key‑separation and transcript binding.
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
    """
    Create a client hello message.

    Parameters
    ----------
    offered : iterable of str, optional
        Cipher suites the client wishes to advertise.  If omitted the
        default ``CLIENT_SUITES`` list is used.

    Returns
    -------
    state : dict
        Holds the private material needed for ``client_finish``.
    hello : bytes
        JSON‑encoded hello message to be sent to the server.

    Raises
    ------
    ValueError
        If any offered suite is not supported (i.e., not a post‑quantum
        suite present in ``KEX``).
    """
    offered = list(offered or CLIENT_SUITES)

    # Reject any suite that we do not implement (including classic algorithms).
    unsupported = [s for s in offered if s not in KEX]
    if unsupported:
        raise ValueError(f"Unsupported cipher suites offered: {unsupported}")

    secrets_, shares = {}, {}
    for suite in offered:
        secret_key, public_key = KEX[suite].keypair()
        secrets_[suite] = secret_key
        shares[suite] = base64.b64encode(public_key).decode()
    hello = json.dumps({"suites": offered, "shares": shares}).encode()
    return {"secrets": secrets_, "hello": hello}, hello


def server_hello(hello):
    """
    Process a client hello and produce a server hello.

    Parameters
    ----------
    hello : bytes
        JSON‑encoded client hello.

    Returns
    -------
    session_key : bytes
        The derived 32‑byte session key.
    suite : str
        The cipher suite selected for this connection.
    reply : bytes
        JSON‑encoded server hello (contains the chosen suite and the server’s
        key share).

    Raises
    ------
    ValueError
        If no mutually supported suite can be found.
    """
    msg = json.loads(hello)

    # Choose the first suite that we both support and that we implement.
    suite = next(
        (
            s
            for s in SERVER_PREFERENCE
            if s in msg["suites"] and s in msg["shares"] and s in KEX
        ),
        None,
    )
    if suite is None:
        raise ValueError("no common cipher suite")

    shared, share = KEX[suite].respond(base64.b64decode(msg["shares"][suite]))
    reply = json.dumps(
        {"suite": suite, "share": base64.b64encode(share).decode()}
    ).encode()
    return _session_key(shared, suite, hello, reply), suite, reply


def client_finish(state, reply):
    """
    Complete the handshake on the client side.

    Parameters
    ----------
    state : dict
        The object returned by ``client_hello``.
    reply : bytes
        JSON‑encoded server hello.

    Returns
    -------
    session_key : bytes
        The derived 32‑byte session key (must match the server’s key).

    Raises
    ------
    ValueError
        If the server selected a suite that the client did not offer.
    """
    msg = json.loads(reply)
    suite = msg["suite"]
    if suite not in state["secrets"]:
        raise ValueError("server chose a suite we did not offer")
    if suite not in KEX:
        # Defensive check – should never happen because client only offers
        # suites present in KEX, but we keep it for robustness.
        raise ValueError("selected suite is not supported")
    secret_key = state["secrets"][suite]
    shared = KEX[suite].finish(secret_key, base64.b64decode(msg["share"]))
    return _session_key(shared, suite, state["hello"], reply)


# --------------------------------------------------------------------------- #
# Secure channel (unchanged)
# --------------------------------------------------------------------------- #
class Channel:
    """AES‑256‑GCM record layer using the derived session key."""

    def __init__(self, session_key):
        self._aead = AESGCM(session_key)

    def seal(self, plaintext):
        """Encrypt ``plaintext`` and prepend the random nonce."""
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, None)

    def open(self, record):
        """Decrypt a record produced by :meth:`seal`."""
        return self._aead.decrypt(record[:12], record[12:], None)
