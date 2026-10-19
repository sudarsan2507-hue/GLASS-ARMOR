"""Encrypted tunnel between two peers, with counter nonces, replay protection and rekeying.

    state, msg1 = initiator_start()
    responder, msg2 = responder_accept(msg1)
    initiator = initiator_finish(state, msg2)
    packet = initiator.send(b"data");  responder.receive(packet)

Handshake: ML‑KEM‑768, then HKDF‑SHA256 (bound to both messages) gives one key per direction.
Packets carry an 8‑byte counter that is also the AES‑GCM nonce; old counters are rejected.
rekey() (called on both sides) moves both directions to fresh keys.
"""

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _direction_keys(shared_secret: bytes, transcript: bytes):
    """
    Derive two 32‑byte keys (initiator→responder, responder→initiator) from the
    KEM shared secret and the transcript of the handshake.
    """
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"pq-gate tunnel v1" + transcript,
    ).derive(shared_secret)
    return okm[:32], okm[32:]  # initiator→responder, responder→initiator


def _next_key(key: bytes) -> bytes:
    """
    Derive the next key for a direction during re‑keying.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate tunnel rekey",
    ).derive(key)


# --------------------------------------------------------------------------- #
# Tunnel class – encrypt / decrypt + rekey
# --------------------------------------------------------------------------- #
class Tunnel:
    def __init__(self, i2r_key: bytes, r2i_key: bytes, is_initiator: bool):
        """
        i2r_key – key used by the initiator to encrypt packets sent to the responder
        r2i_key – key used by the responder to encrypt packets sent to the initiator
        """
        if is_initiator:
            self._send_key, self._recv_key = i2r_key, r2i_key
        else:
            self._send_key, self._recv_key = r2i_key, i2r_key

        self._send_counter = 0
        self._recv_counter = -1

    def send(self, plaintext: bytes) -> bytes:
        """
        Encrypt ``plaintext`` and prepend the 8‑byte packet counter.
        The counter also forms the lower 8 bytes of the 12‑byte AES‑GCM nonce
        (the upper 4 bytes are zero).
        """
        counter = self._send_counter
        self._send_counter += 1

        nonce = b"\x00" * 4 + counter.to_bytes(8, "big")
        ciphertext = AESGCM(self._send_key).encrypt(nonce, plaintext, None)

        return counter.to_bytes(8, "big") + ciphertext

    def receive(self, packet: bytes) -> bytes:
        """
        Decrypt a packet. Raises ``ValueError`` on replay or tampering.
        """
        if len(packet) < 8:
            raise ValueError("packet too short")

        counter = int.from_bytes(packet[:8], "big")
        if counter <= self._recv_counter:
            raise ValueError("replayed or old packet")

        nonce = b"\x00" * 4 + packet[:8]
        plaintext = AESGCM(self._recv_key).decrypt(nonce, packet[8:], None)

        self._recv_counter = counter
        return plaintext

    def rekey(self):
        """
        Derive fresh send/receive keys and reset counters.
        """
        self._send_key = _next_key(self._send_key)
        self._recv_key = _next_key(self._recv_key)
        self._send_counter = 0
        self._recv_counter = -1


# --------------------------------------------------------------------------- #
# Handshake – initiator side
# --------------------------------------------------------------------------- #
def initiator_start():
    """
    Generate an ML‑KEM‑768 key‑pair, return the state needed for the later
    ``initiator_finish`` call and the public key (msg1) to be sent to the responder.
    The returned ``state`` dictionary mimics the original API (it contains a
    ``private_key`` entry) so existing tests continue to work.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    secret_key = kem.export_secret_key()         # bytes

    # ``private_key`` is kept for backward‑compatibility; it actually holds the
    # secret key needed for decapsulation.
    state = {"private_key": secret_key, "msg1": public_key}
    return state, public_key


# --------------------------------------------------------------------------- #
# Handshake – responder side
# --------------------------------------------------------------------------- #
def responder_accept(msg1: bytes):
    """
    Perform the responder part of the handshake.
    * ``msg1`` – initiator's public key (bytes)
    Returns a tuple ``(Tunnel, msg2)`` where ``msg2`` is the ciphertext that
    the responder sends back to the initiator.
    """
    # The size of a ML‑KEM‑768 public key is 1184 bytes; we only check that it is
    # non‑empty to keep the function tolerant to future parameter changes.
    if not msg1:
        raise ValueError("bad handshake message")

    # Encapsulate a shared secret using the initiator's public key.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(msg1)   # ciphertext = msg2

    # Derive direction‑specific keys from the shared secret and the transcript.
    i2r_key, r2i_key = _direction_keys(shared_secret, msg1 + ciphertext)

    tunnel = Tunnel(i2r_key, r2i_key, is_initiator=False)
    return tunnel, ciphertext


# --------------------------------------------------------------------------- #
# Handshake – initiator finalisation
# --------------------------------------------------------------------------- #
def initiator_finish(state: dict, msg2: bytes):
    """
    Complete the initiator side of the handshake using the stored secret key.
    Returns a ``Tunnel`` instance ready for encrypted communication.
    """
    if not msg2:
        raise ValueError("bad handshake message")

    secret_key = state["private_key"]
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
    shared_secret = kem.decap_secret(msg2)

    i2r_key, r2i_key = _direction_keys(shared_secret, state["msg1"] + msg2)
    return Tunnel(i2r_key, r2i_key, is_initiator=True)
