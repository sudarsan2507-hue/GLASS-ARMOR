from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.dsa import DSAKey, DSAParameterGenerator, DSA
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature


def _raw(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _direction_keys(shared_secret, transcript):
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None,
               info=b"pq-gate tunnel v1" + transcript).derive(shared_secret)
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
    msg1 = _raw(private_key.public_key())
    return {"private_key": private_key, "msg1": msg1}, msg1


def responder_accept(msg1):
    """Returns (Tunnel, msg2)."""
    if len(msg1) != 32:
        raise ValueError("bad handshake message")
    private_key = X25519PrivateKey.generate()
    msg2 = _raw(private_key.public_key())
    shared = private_key.exchange(X25519PublicKey.from_public_bytes(msg1))
    return Tunnel(*_direction_keys(shared, msg1 + msg2), is_initiator=False), msg2


def initiator_finish(state, msg2):
    """Returns the initiator's Tunnel."""
    if len(msg2) != 32:
        raise ValueError("bad handshake message")
    shared = state["private_key"].exchange(X25519PublicKey.from_public_bytes(msg2))
    return Tunnel(*_direction_keys(shared, state["msg1"] + msg2), is_initiator=True)


def dsa_keygen():
    generator = DSAParameterGenerator()
    generator.generate_parameters(hashes.SHA256())
    private_key = generator.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def dsa_sign(private_key, message):
    signature = private_key.sign(message, hashes.SHA256())
    return encode_dss_signature(signature)


def dsa_verify(public_key, message, signature):
    try:
        decode_dss_signature(signature)
        return public_key.verify(signature, message, hashes.SHA256())
    except ValueError:
        return False
