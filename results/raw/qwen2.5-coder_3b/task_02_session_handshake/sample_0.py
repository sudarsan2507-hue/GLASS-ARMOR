"""Session key setup between a client and a server, plus an encrypted message channel.

Handshake (X25519 key agreement):
    state, client_hello = client_start()
    session_key, server_hello = server_respond(client_hello)    # on the server
    session_key = client_finish(state, server_hello)            # on the client
The session key comes from HKDF-SHA256 over the X25519 shared secret, bound to
both hello messages. SecureChannel then encrypts messages with AES-256-GCM.
"""
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.dsa import DSAKeyPairGenerator, DSAParameterGenerator, DSA
from cryptography.hazmat.primitives.asymmetric import padding


def _raw(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _session_key(shared_secret, transcript):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate session v1" + transcript).derive(shared_secret)


def client_start():
    """Start a handshake. Returns (client_state, client_hello)."""
    private_key = X25519PrivateKey.generate()
    client_hello = _raw(private_key.public_key())
    return {"private_key": private_key, "client_hello": client_hello}, client_hello


def server_respond(client_hello):
    """Answer a client hello. Returns (session_key, server_hello)."""
    if len(client_hello) != 32:
        raise ValueError("bad client hello")
    private_key = X25519PrivateKey.generate()
    server_hello = _raw(private_key.public_key())
    shared = private_key.exchange(X25519PublicKey.from_public_bytes(client_hello))
    return _session_key(shared, client_hello + server_hello), server_hello


def client_finish(client_state, server_hello):
    """Finish the handshake on the client. Returns session_key."""
    if len(server_hello) != 32:
        raise ValueError("bad server hello")
    peer = X25519PublicKey.from_public_bytes(server_hello)
    shared = client_state["private_key"].exchange(peer)
    return _session_key(shared, client_state["client_hello"] + server_hello)


class SecureChannel:
    """Encrypts and decrypts messages under a session key (AES-256-GCM)."""

    def __init__(self, session_key):
        self._aead = AESGCM(session_key)

    def encrypt(self, plaintext, aad=b""):
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, message, aad=b""):
        """Raises if the message was tampered with or the key/aad is wrong."""
        return self._aead.decrypt(message[:12], message[12:], aad)


class DSAKeyPair:
    """DSA key pair for signing and verification."""

    def __init__(self, private_key, public_key):
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def generate(cls):
        generator = DSAParameterGenerator()
        generator.set_key_size(65)
        params = generator.generate_parameters()
        private_key = params.generate_private_key()
        public_key = private_key.public_key()
        return cls(private_key, public_key)

    def sign(self, message):
        return self._private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    def verify(self, message, signature, public_key):
        return public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
