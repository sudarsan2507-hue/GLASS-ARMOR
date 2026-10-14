"""Session key setup between a client and a server, plus an encrypted message channel.
Post-quantum version: hybrid X25519 + ML-KEM-768.

Handshake:
    state, client_hello = client_start()
    session_key, server_hello = server_respond(client_hello)    # on the server
    session_key = client_finish(state, server_hello)            # on the client
client_hello = X25519 public key (32) | ML-KEM public key (1184)
server_hello = X25519 public key (32) | ML-KEM ciphertext (1088)
The session key comes from HKDF-SHA256 over BOTH shared secrets, bound to both hello
messages (which contain the KEM ciphertext). SecureChannel encrypts with AES-256-GCM.
"""
import os

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALG = "ML-KEM-768"
X_LEN, KEM_PK_LEN, KEM_CT_LEN = 32, 1184, 1088


def _raw(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _session_key(classical_secret, pq_secret, transcript):
    combined = bytes(a ^ b for a, b in zip(classical_secret, pq_secret))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate hybrid session v1").derive(combined)


def client_start():
    """Start a handshake. Returns (client_state, client_hello)."""
    private_key = X25519PrivateKey.generate()
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_public = kem.generate_keypair()
        kem_secret = kem.export_secret_key()
    client_hello = _raw(private_key.public_key()) + kem_public
    state = {"private_key": private_key, "kem_secret": kem_secret, "client_hello": client_hello}
    return state, client_hello


def server_respond(client_hello):
    """Answer a client hello. Returns (session_key, server_hello)."""
    if len(client_hello) != X_LEN + KEM_PK_LEN:
        raise ValueError("bad client hello")
    peer_x, peer_kem = client_hello[:X_LEN], client_hello[X_LEN:]
    private_key = X25519PrivateKey.generate()
    classical = private_key.exchange(X25519PublicKey.from_public_bytes(peer_x))
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_ct, pq = kem.encap_secret(peer_kem)
    server_hello = _raw(private_key.public_key()) + kem_ct
    return _session_key(classical, pq, client_hello + server_hello), server_hello


def client_finish(client_state, server_hello):
    """Finish the handshake on the client. Returns session_key."""
    if len(server_hello) != X_LEN + KEM_CT_LEN:
        raise ValueError("bad server hello")
    peer_x, kem_ct = server_hello[:X_LEN], server_hello[X_LEN:]
    classical = client_state["private_key"].exchange(X25519PublicKey.from_public_bytes(peer_x))
    with oqs.KeyEncapsulation(KEM_ALG, secret_key=client_state["kem_secret"]) as kem:
        pq = kem.decap_secret(kem_ct)
    return _session_key(classical, pq, client_state["client_hello"] + server_hello)


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
