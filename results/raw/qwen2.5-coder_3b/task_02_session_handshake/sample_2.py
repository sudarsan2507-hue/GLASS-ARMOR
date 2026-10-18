import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.dsa import DSAParameterGenerator, DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature


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


class DSAHandshake:
    """Handles the DSA key exchange and signature operations."""

    def __init__(self, dsa_params):
        self._dsa_params = dsa_params

    def generate_keypair(self):
        private_key = DSAPrivateKey.generate_parameters(self._dsa_params).generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def export_secret_key(self, private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def sign(self, message, private_key):
        signature = private_key.sign(
            message,
            algorithm=hashes.SHA256(),
            mgf=hashes.MGF1(algorithm=hashes.SHA256()),
            label=None
        )
        return encode_dss_signature(signature)

    def verify(self, message, signature, public_key):
        try:
            decoded_signature = decode_dss_signature(signature)
            public_key.verify(
                decoded_signature,
                message,
                algorithm=hashes.SHA256(),
                mgf=hashes.MGF1(algorithm=hashes.SHA256()),
                label=None
            )
            return True
        except Exception:
            return False

    def sign_with_ctx_str(self, message, context, private_key):
        signature = private_key.sign(
            message,
            algorithm=hashes.SHA256(),
            mgf=hashes.MGF1(algorithm=hashes.SHA256()),
            label=context
        )
        return encode_dss_signature(signature)

    def verify_with_ctx_str(self, message, signature, context, public_key):
        try:
            decoded_signature = decode_dss_signature(signature)
            public_key.verify(
                decoded_signature,
                message,
                algorithm=hashes.SHA256(),
                mgf=hashes.MGF1(algorithm=hashes.SHA256()),
                label=context
            )
            return True
        except Exception:
            return False
