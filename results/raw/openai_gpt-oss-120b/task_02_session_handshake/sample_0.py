"""Session key setup between a client and a server, plus an encrypted message channel.

Handshake (ML‑KEM‑768 key encapsulation):
    state, client_hello = client_start()
    session_key, server_hello = server_respond(client_hello)   # on the server
    session_key = client_finish(state, server_hello)          # on the client

The session key comes from HKDF‑SHA256 over the KEM shared secret, bound to
both hello messages. SecureChannel then encrypts messages with AES‑256‑GCM.
"""

import os

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --------------------------------------------------------------------------- #
# Helper utilities
# --------------------------------------------------------------------------- #
def _session_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """Derive a 32‑byte session key from a KEM shared secret and transcript."""
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
    """Start a handshake.

    Returns
    -------
    tuple
        (client_state, client_hello)

    * ``client_state`` – opaque dict that must be passed unchanged to
      :func:`client_finish`.
    * ``client_hello`` – the public key (bytes) that the client sends to the
      server.
    """
    # Generate a fresh ML‑KEM‑768 key pair.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    client_hello = kem.generate_keypair()          # public key (bytes)
    secret_key = kem.export_secret_key()           # secret key (bytes)

    # Store only what we need for decapsulation; the KEM object itself can be
    # discarded – the secret key is sufficient.
    client_state = {
        "secret_key": secret_key,
        "client_hello": client_hello,
    }
    return client_state, client_hello


def server_respond(client_hello: bytes):
    """Answer a client hello.

    Parameters
    ----------
    client_hello : bytes
        The public key received from the client.

    Returns
    -------
    tuple
        (session_key, server_hello)

    * ``session_key`` – 32‑byte key derived from the KEM shared secret.
    * ``server_hello`` – the ciphertext (bytes) that the client will decapsulate.
    """
    if not isinstance(client_hello, (bytes, bytearray)):
        raise TypeError("client_hello must be bytes")
    # Perform encapsulation using the client's public key.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    server_hello, shared_secret = kem.encap_secret(client_hello)

    # Derive the session key, binding both hello messages.
    session_key = _session_key(shared_secret, client_hello + server_hello)
    return session_key, server_hello


def client_finish(client_state: dict, server_hello: bytes):
    """Finish the handshake on the client.

    Parameters
    ----------
    client_state : dict
        The opaque state returned by :func:`client_start`.
    server_hello : bytes
        The ciphertext received from the server.

    Returns
    -------
    bytes
        The 32‑byte session key.
    """
    if not isinstance(server_hello, (bytes, bytearray)):
        raise TypeError("server_hello must be bytes")
    secret_key = client_state.get("secret_key")
    if secret_key is None:
        raise ValueError("client_state missing secret_key")

    # Decapsulate to obtain the shared secret.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
    shared_secret = kem.decap_secret(server_hello)

    # Re‑create the transcript used by the server.
    client_hello = client_state.get("client_hello", b"")
    session_key = _session_key(shared_secret, client_hello + server_hello)
    return session_key


# --------------------------------------------------------------------------- #
# Secure channel (AES‑256‑GCM)
# --------------------------------------------------------------------------- #
class SecureChannel:
    """Encrypts and decrypts messages under a session key (AES‑256‑GCM)."""

    def __init__(self, session_key: bytes):
        if len(session_key) != 32:
            raise ValueError("session_key must be 32 bytes for AES‑256‑GCM")
        self._aead = AESGCM(session_key)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt ``plaintext`` and prepend the random nonce.

        Returns
        -------
        bytes
            ``nonce || ciphertext || tag`` (nonce is 12 bytes).
        """
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, message: bytes, aad: bytes = b"") -> bytes:
        """Decrypt a message produced by :meth:`encrypt`.

        Raises
        ------
        cryptography.exceptions.InvalidTag
            If authentication fails.
        """
        nonce, ciphertext = message[:12], message[12:]
        return self._aead.decrypt(nonce, ciphertext, aad)
