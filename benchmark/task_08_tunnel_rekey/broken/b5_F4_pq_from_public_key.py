"""Encrypted tunnel between two peers, with counter nonces, replay protection and rekeying.
Post-quantum version: hybrid X25519 + ML-KEM-768 handshake.

    state, msg1 = initiator_start()
    responder, msg2 = responder_accept(msg1)
    initiator = initiator_finish(state, msg2)
    packet = initiator.send(b"data");  responder.receive(packet)
msg1 = X25519 public key (32) | ML-KEM public key (1184)
msg2 = X25519 public key (32) | ML-KEM ciphertext (1088)
HKDF-SHA256 over both shared secrets (bound to both messages) gives one key per direction.
Packets carry an 8-byte counter that is also the AES-GCM nonce; old counters are rejected.
rekey() (called on both sides) moves both directions to fresh keys.
"""
import hashlib

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALG = "ML-KEM-768"
X_LEN, KEM_PK_LEN, KEM_CT_LEN = 32, 1184, 1088


def _raw(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _direction_keys(classical_secret, pq_secret, transcript):
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None,
               info=b"pq-gate hybrid tunnel v1" + transcript).derive(classical_secret + pq_secret)
    return okm[:32], okm[32:]  # initiator->responder, responder->initiator


def _next_key(key):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate tunnel rekey").derive(key)


class Tunnel:
    def __init__(self, i2r_key, r2i_key, is_initiator):
        self._send_key, self._recv_key = (i2r_key, r2i_key) if is_initiator else (r2i_key, i2r_key)
        self._send_counter, self._recv_counter = 0, -1

    def send(self, plaintext):
        counter = self._send_counter
        self._send_counter += 1
        nonce = b"\x00" * 4 + counter.to_bytes(8, "big")
        return counter.to_bytes(8, "big") + AESGCM(self._send_key).encrypt(nonce, plaintext, None)

    def receive(self, packet):
        """Decrypt a packet. Raises on tampering, wrong key or replay."""
        counter = int.from_bytes(packet[:8], "big")
        if counter <= self._recv_counter:
            raise ValueError("replayed or old packet")
        nonce = b"\x00" * 4 + packet[:8]
        plaintext = AESGCM(self._recv_key).decrypt(nonce, packet[8:], None)
        self._recv_counter = counter
        return plaintext

    def rekey(self):
        self._send_key, self._recv_key = _next_key(self._send_key), _next_key(self._recv_key)
        self._send_counter, self._recv_counter = 0, -1


def initiator_start():
    private_key = X25519PrivateKey.generate()
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_public = kem.generate_keypair()
        kem_secret = kem.export_secret_key()
    msg1 = _raw(private_key.public_key()) + kem_public
    return {"private_key": private_key, "kem_secret": kem_secret, "msg1": msg1}, msg1


def responder_accept(msg1):
    """Returns (Tunnel, msg2)."""
    if len(msg1) != X_LEN + KEM_PK_LEN:
        raise ValueError("bad handshake message")
    private_key = X25519PrivateKey.generate()
    classical = private_key.exchange(X25519PublicKey.from_public_bytes(msg1[:X_LEN]))
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_ct, pq = kem.encap_secret(msg1[X_LEN:])
    msg2 = _raw(private_key.public_key()) + kem_ct
    return Tunnel(*_direction_keys(classical, hashlib.sha256(msg1[X_LEN:]).digest(), msg1 + msg2), is_initiator=False), msg2


def initiator_finish(state, msg2):
    """Returns the initiator's Tunnel."""
    if len(msg2) != X_LEN + KEM_CT_LEN:
        raise ValueError("bad handshake message")
    classical = state["private_key"].exchange(X25519PublicKey.from_public_bytes(msg2[:X_LEN]))
    with oqs.KeyEncapsulation(KEM_ALG, secret_key=state["kem_secret"]) as kem:
        pq = kem.decap_secret(msg2[X_LEN:])
    return Tunnel(*_direction_keys(classical, hashlib.sha256(state["msg1"][X_LEN:]).digest(), state["msg1"] + msg2), is_initiator=True)
