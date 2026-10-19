"""Post‑quantum session key setup between a client and a server, plus an encrypted
message channel.

Handshake (ML‑KEM‑768 key encapsulation):
    state, client_hello = client_start()
    session_key, server_hello = server_respond(client_hello)   # on the server
    session_key = client_finish(state, server_hello)          # on the client

The session key is derived with HKDF‑SHA256 over the KEM shared secret, bound to
both hello messages.  SecureChannel then encrypts messages with AES‑256‑GCM.
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
    """Derive a 32‑byte session key from a KEM shared secret and the transcript."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate session v1" + transcript,
    ).derive(shared_secret)


# --------------------------------------------------------------------------- #
# Hand‑shake API (public, unchanged signature)
# --------------------------------------------------------------------------- #
def client_start():
    """Start a handshake. Returns (client_state, client_hello).

    * client_state – opaque dict kept by the client.
    * client_hello – the public key (bytes) that will be sent to the server.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    client_hello = kem.generate_keypair()          # public key (bytes)
    secret_key = kem.export_secret_key()           # private key (bytes)

    # Store only what we need for the later decapsulation.
    client_state = {
        "secret_key": secret_key,
        "client_hello": client_hello,
    }
    return client_state, client_hello


def server_respond(client_hello: bytes):
    """Answer a client hello. Returns (session_key, server_hello).

    * server_hello – the server's public key concatenated with the ciphertext
      that the client must decapsulate.  The format is:
          server_public_key || ciphertext
    """
    if len(client_hello) != 32:
        raise ValueError("bad client hello")

    # Server generates its own KEM keypair.
    server_kem = oqs.KeyEncapsulation("ML-KEM-768")
    server_hello_pub = server_kem.generate_keypair()   # 32‑byte public key
    server_secret_key = server_kem.export_secret_key()  # not needed further

    # Encapsulate a shared secret to the client’s public key.
    ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(
        client_hello
    )

    # Derive the session key, binding both hello messages.
    transcript = client_hello + server_hello_pub + ciphertext
    session_key = _session_key(shared_secret, transcript)

    # The server sends its public key followed by the ciphertext.
    server_hello = server_hello_pub + ciphertext
    return session_key, server_hello


def client_finish(client_state: dict, server_hello: bytes):
    """Finish the handshake on the client. Returns the session_key."""
    if len(server_hello) < 32:
        raise ValueError("bad server hello")

    # Split the server’s message.
    server_pub = server_hello[:32]          # not used, but kept for symmetry
    ciphertext = server_hello[32:]

    # Decapsulate using the client’s secret key.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=client_state["secret_key"])
    shared_secret = kem.decap_secret(ciphertext)

    # Derive the same session key as the server did.
    transcript = client_state["client_hello"] + server_pub + ciphertext
    return _session_key(shared_secret, transcript)


# --------------------------------------------------------------------------- #
# Secure channel (unchanged)
# --------------------------------------------------------------------------- #
class SecureChannel:
    """Encrypts and decrypts messages under a session key (AES‑256‑GCM)."""

    def __init__(self, session_key: bytes):
        self._aead = AESGCM(session_key)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt `plaintext` and prepend the random nonce."""
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, message: bytes, aad: bytes = b"") -> bytes:
        """Decrypt `message`. Raises if tampered with or wrong key/AAD."""
        return self._aead.decrypt(message[:12], message[12:], aad)
