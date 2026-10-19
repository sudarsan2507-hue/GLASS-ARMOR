"""Session key setup between a client and a server, plus an encrypted message channel.

Handshake (ML‑KEM‑768 post‑quantum key encapsulation):
    state, client_hello = client_start()
    session_key, server_hello = server_respond(client_hello)   # on the server
    session_key = client_finish(state, server_hello)           # on the client

The session key comes from HKDF‑SHA256 over the shared secret produced by the
KEM, bound to both hello messages.  SecureChannel then encrypts messages with
AES‑256‑GCM.
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
    """Derive a 32‑byte session key from a KEM shared secret and transcript."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate session v1" + transcript,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
# Handshake API (public functions)
# --------------------------------------------------------------------------- #
def client_start():
    """Start a handshake.

    Returns
    -------
    tuple[dict, bytes]
        ``client_state`` – a dict containing the secret key needed for decapsulation.
        ``client_hello`` – the public key (bytes) that will be sent to the server.
    """
    # Generate a fresh ML‑KEM‑768 keypair.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    secret_key = kem.export_secret_key()         # bytes

    # Store only what we need for the later decapsulation step.
    client_state = {"secret_key": secret_key, "client_hello": public_key}
    return client_state, public_key


def server_respond(client_hello: bytes):
    """Answer a client hello.

    Parameters
    ----------
    client_hello : bytes
        The public key received from the client.

    Returns
    -------
    tuple[bytes, bytes]
        ``session_key`` – the derived 32‑byte session key.
        ``server_hello`` – the ciphertext (bytes) that carries the encapsulated secret.
    """
    if not isinstance(client_hello, (bytes, bytearray)):
        raise TypeError("client_hello must be bytes")
    # Encapsulate a shared secret using the client's public key.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(client_hello)

    # Derive the session key, binding both hello messages.
    transcript = client_hello + ciphertext
    session_key = _session_key(shared_secret, transcript)
    return session_key, ciphertext


def client_finish(client_state: dict, server_hello: bytes):
    """Finish the handshake on the client.

    Parameters
    ----------
    client_state : dict
        The state returned by :func:`client_start`.
    server_hello : bytes
        The ciphertext received from the server.

    Returns
    -------
    bytes
        The derived 32‑byte session key.
    """
    if not isinstance(server_hello, (bytes, bytearray)):
        raise TypeError("server_hello must be bytes")
    secret_key = client_state.get("secret_key")
    if secret_key is None:
        raise ValueError("client_state missing secret_key")

    # Decapsulate to obtain the same shared secret the server derived.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
    shared_secret = kem.decap_secret(server_hello)

    # Re‑create the transcript exactly as the server did.
    client_hello = client_state.get("client_hello")
    if client_hello is None:
        raise ValueError("client_state missing client_hello")
    transcript = client_hello + server_hello
    return _session_key(shared_secret, transcript)


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
        if len(message) < 12:
            raise ValueError("message too short to contain nonce")
        nonce, ciphertext = message[:12], message[12:]
        return self._aead.decrypt(nonce, ciphertext, aad)
