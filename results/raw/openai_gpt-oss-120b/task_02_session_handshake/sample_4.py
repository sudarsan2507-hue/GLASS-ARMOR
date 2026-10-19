"""Session key setup between a client and a server, plus an encrypted message channel.

Handshake (ML‑KEM‑768 post‑quantum key encapsulation):
    state, client_hello = client_start()
    session_key, server_hello = server_respond(client_hello)    # on the server
    session_key = client_finish(state, server_hello)            # on the client
The session key comes from HKDF‑SHA256 over the shared secret produced by the
KEM, bound to both hello messages. SecureChannel then encrypts messages with
AES‑256‑GCM.
"""

import os

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- #
# ML‑KEM‑768 parameters (as defined by liboqs)
# --------------------------------------------------------------------------- #
_KEM_NAME = "ML-KEM-768"
_KEM = oqs.KeyEncapsulation(_KEM_NAME)

# Sizes in bytes – taken from liboqs documentation
_PUBLIC_KEY_SIZE = _KEM.length_public_key   # 1184 for ML‑KEM‑768
_CIPHERTEXT_SIZE = _KEM.length_ciphertext   # 1088 for ML‑KEM‑768
_SHARED_SECRET_SIZE = _KEM.length_shared_secret  # 32 bytes


def _raw(public_key_bytes: bytes) -> bytes:
    """Return the raw public key bytes (identity function for KEM keys)."""
    return public_key_bytes


def _session_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """Derive a 32‑byte session key from the KEM shared secret and transcript."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate session v1" + transcript,
    ).derive(shared_secret)


def client_start():
    """Start a handshake. Returns (client_state, client_hello).

    client_state holds the secret key needed for decapsulation.
    client_hello is the public key that will be sent to the server.
    """
    # Generate an ML‑KEM‑768 key pair for the client
    client_kem = oqs.KeyEncapsulation(_KEM_NAME)
    client_public = client_kem.generate_keypair()          # bytes
    client_secret = client_kem.export_secret_key()        # bytes

    # Store only what is needed for later: the secret key (bytes)
    client_state = {
        "secret_key": client_secret,
        "client_hello": _raw(client_public),
    }
    return client_state, client_public


def server_respond(client_hello: bytes):
    """Answer a client hello. Returns (session_key, server_hello).

    server_hello is the concatenation of the server's public key and the
    ciphertext that encapsulates a shared secret for the client.
    """
    if len(client_hello) != _PUBLIC_KEY_SIZE:
        raise ValueError("bad client hello length")

    # Server generates its own ML‑KEM‑768 key pair
    server_kem = oqs.KeyEncapsulation(_KEM_NAME)
    server_public = server_kem.generate_keypair()          # bytes

    # Encapsulate a shared secret for the client using the client's public key
    ciphertext, shared_secret = oqs.KeyEncapsulation(_KEM_NAME).encap_secret(
        client_hello
    )

    # Build the server hello: public key || ciphertext
    server_hello = server_public + ciphertext

    # Derive the session key from the shared secret and the transcript
    session_key = _session_key(shared_secret, client_hello + server_hello)
    return session_key, server_hello


def client_finish(client_state: dict, server_hello: bytes):
    """Finish the handshake on the client. Returns the session_key."""
    expected_len = _PUBLIC_KEY_SIZE + _CIPHERTEXT_SIZE
    if len(server_hello) != expected_len:
        raise ValueError("bad server hello length")

    # Split the server hello into its components
    server_public = server_hello[:_PUBLIC_KEY_SIZE]
    ciphertext = server_hello[_PUBLIC_KEY_SIZE : _PUBLIC_KEY_SIZE + _CIPHERTEXT_SIZE]

    # Decapsulate the ciphertext using the client's secret key
    kem = oqs.KeyEncapsulation(_KEM_NAME, secret_key=client_state["secret_key"])
    shared_secret = kem.decap_secret(ciphertext)

    # Derive the session key using the same transcript as the server
    transcript = client_state["client_hello"] + server_hello
    return _session_key(shared_secret, transcript)


class SecureChannel:
    """Encrypts and decrypts messages under a session key (AES‑256‑GCM)."""

    def __init__(self, session_key: bytes):
        if len(session_key) != 32:
            raise ValueError("session_key must be 32 bytes for AES‑256‑GCM")
        self._aead = AESGCM(session_key)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt `plaintext` and prepend the random nonce."""
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, message: bytes, aad: bytes = b"") -> bytes:
        """Decrypt `message`. Raises if tampered with or wrong key/AAD."""
        nonce, ciphertext = message[:12], message[12:]
        return self._aead.decrypt(nonce, ciphertext, aad)
