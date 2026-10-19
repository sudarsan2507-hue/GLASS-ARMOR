"""Session key setup between a client and a server, plus an encrypted message channel.

Handshake (ML‑KEM‑768 post‑quantum key encapsulation):
    state, client_hello = client_start()
    session_key, server_hello = server_respond(client_hello)   # on the server
    session_key = client_finish(state, server_hello)          # on the client

The session key comes from HKDF‑SHA256 over the ML‑KEM shared secret, bound to
both hello messages. SecureChannel then encrypts messages with AES‑256‑GCM.
"""

import os

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _session_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """
    Derive a 32‑byte session key from the KEM shared secret and the transcript
    (client_hello || server_hello) using HKDF‑SHA256.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate session v1" + transcript,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
# Handshake primitives (post‑quantum)
# --------------------------------------------------------------------------- #
def client_start():
    """
    Start a handshake.

    Returns
    -------
    tuple
        (client_state, client_hello)

    * ``client_state`` – a dict that holds the secret key and the public key
      (client_hello). It is opaque to callers.
    * ``client_hello`` – the public key that will be sent to the server.
    """
    # Generate a fresh ML‑KEM‑768 keypair.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    client_hello = kem.generate_keypair()          # public key (bytes)
    secret_key = kem.export_secret_key()           # secret key (bytes)

    # Store only what we need for the later decapsulation step.
    client_state = {
        "secret_key": secret_key,
        "client_hello": client_hello,
    }
    return client_state, client_hello


def server_respond(client_hello: bytes):
    """
    Answer a client hello.

    Parameters
    ----------
    client_hello : bytes
        The public key received from the client.

    Returns
    -------
    tuple
        (session_key, server_hello)

    * ``session_key`` – the 32‑byte key derived from the KEM shared secret.
    * ``server_hello`` – the ciphertext that the client will decapsulate.
    """
    # Perform encapsulation using the client's public key.
    server_kem = oqs.KeyEncapsulation("ML-KEM-768")
    server_hello, shared_secret = server_kem.encap_secret(client_hello)

    # Derive the session key, binding both hello messages.
    session_key = _session_key(shared_secret, client_hello + server_hello)
    return session_key, server_hello


def client_finish(client_state: dict, server_hello: bytes):
    """
    Finish the handshake on the client side.

    Parameters
    ----------
    client_state : dict
        The state returned by :func:`client_start`.
    server_hello : bytes
        The ciphertext received from the server.

    Returns
    -------
    bytes
        The 32‑byte session key.
    """
    # Re‑create a KEM object that knows the secret key.
    client_kem = oqs.KeyEncapsulation(
        "ML-KEM-768", secret_key=client_state["secret_key"]
    )
    shared_secret = client_kem.decap_secret(server_hello)

    # Derive the same session key as the server.
    session_key = _session_key(
        shared_secret,
        client_state["client_hello"] + server_hello,
    )
    return session_key


# --------------------------------------------------------------------------- #
# Secure channel (AES‑256‑GCM)
# --------------------------------------------------------------------------- #
class SecureChannel:
    """Encrypts and decrypts messages under a session key (AES‑256‑GCM)."""

    def __init__(self, session_key: bytes):
        self._aead = AESGCM(session_key)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt ``plaintext`` with optional additional authenticated data ``aad``.

        Returns
        -------
        bytes
            ``nonce || ciphertext || tag`` (nonce is 12 random bytes).
        """
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, message: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt a message produced by :meth:`encrypt`.

        Raises
        ------
        cryptography.exceptions.InvalidTag
            If authentication fails (tampered ciphertext, wrong key, or wrong AAD).
        """
        return self._aead.decrypt(message[:12], message[12:], aad)
