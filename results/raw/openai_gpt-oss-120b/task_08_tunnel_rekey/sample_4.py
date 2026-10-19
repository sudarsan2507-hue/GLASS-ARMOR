"""Encrypted tunnel between two peers, with counter nonces, replay protection and rekeying.

    state, msg1 = initiator_start()
    responder, msg2 = responder_accept(msg1)
    initiator = initiator_finish(state, msg2)
    packet = initiator.send(b"data");  responder.receive(packet)

Handshake: ML‑KEM‑768, then HKDF‑SHA256 (bound to both messages) gives one key per direction.
Packets carry an 8‑byte counter that is also the AES‑GCM nonce; old counters are rejected.
rekey() (called on both sides) moves both directions to fresh keys.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import oqs  # liboqs‑python


def _direction_keys(shared_secret: bytes, transcript: bytes):
    """Derive two 32‑byte keys (initiator→responder, responder→initiator) from the
    shared secret and the transcript of the handshake."""
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"pq-gate tunnel v1" + transcript,
    ).derive(shared_secret)
    return okm[:32], okm[32:]


def _next_key(key: bytes) -> bytes:
    """Derive the next key for re‑keying."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate tunnel rekey",
    ).derive(key)


class Tunnel:
    """Stateful encrypt‑/decrypt‑only channel."""

    def __init__(self, i2r_key: bytes, r2i_key: bytes, is_initiator: bool):
        # Choose the correct direction for each side.
        self._send_key, self._recv_key = (
            (i2r_key, r2i_key) if is_initiator else (r2i_key, i2r_key)
        )
        self._send_counter = 0
        self._recv_counter = -1

    def send(self, plaintext: bytes) -> bytes:
        """Encrypt *plaintext* and prepend the 8‑byte counter."""
        counter = self._send_counter
        self._send_counter += 1
        # 4 zero bytes + 8‑byte counter = 12‑byte AES‑GCM nonce.
        nonce = b"\x00" * 4 + counter.to_bytes(8, "big")
        ciphertext = AESGCM(self._send_key).encrypt(nonce, plaintext, None)
        return counter.to_bytes(8, "big") + ciphertext

    def receive(self, packet: bytes) -> bytes:
        """Decrypt a packet. Raises on tampering, wrong key or replay."""
        counter = int.from_bytes(packet[:8], "big")
        if counter <= self._recv_counter:
            raise ValueError("replayed or old packet")
        nonce = b"\x00" * 4 + packet[:8]
        plaintext = AESGCM(self._recv_key).decrypt(nonce, packet[8:], None)
        self._recv_counter = counter
        return plaintext

    def rekey(self) -> None:
        """Refresh both send and receive keys."""
        self._send_key = _next_key(self._send_key)
        self._recv_key = _next_key(self._recv_key)
        self._send_counter = 0
        self._recv_counter = -1


def initiator_start():
    """
    Generate an ML‑KEM‑768 key pair and return the handshake state and the
    initiator's public key (msg1).

    Returns
    -------
    state : dict
        Contains the KEM object (with secret key) and the raw public key.
    msg1 : bytes
        The public key that must be sent to the responder.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    # The KEM object now holds the secret key internally; we keep a reference.
    state = {"kem": kem, "msg1": public_key}
    return state, public_key


def responder_accept(msg1: bytes):
    """
    Perform the responder side of the handshake.

    Parameters
    ----------
    msg1 : bytes
        The initiator's public key (output of ``initiator_start``).

    Returns
    -------
    tunnel : Tunnel
        A fully‑initialised tunnel ready to receive packets.
    msg2 : bytes
        The ciphertext that must be sent back to the initiator.
    """
    if not isinstance(msg1, (bytes, bytearray)):
        raise ValueError("bad handshake message")
    # Encapsulate a shared secret using the initiator's public key.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(public_key=msg1)
    # Derive direction‑specific keys from the shared secret and the transcript.
    i2r_key, r2i_key = _direction_keys(shared_secret, msg1 + ciphertext)
    tunnel = Tunnel(i2r_key, r2i_key, is_initiator=False)
    return tunnel, ciphertext


def initiator_finish(state: dict, msg2: bytes):
    """
    Complete the initiator side of the handshake.

    Parameters
    ----------
    state : dict
        The object returned by ``initiator_start``.
    msg2 : bytes
        The ciphertext received from the responder.

    Returns
    -------
    tunnel : Tunnel
        A fully‑initialised tunnel ready to send packets.
    """
    if not isinstance(msg2, (bytes, bytearray)):
        raise ValueError("bad handshake message")
    kem = state.get("kem")
    if kem is None:
        raise ValueError("invalid initiator state")
    # Decapsulate to obtain the shared secret.
    shared_secret = kem.decap_secret(msg2)
    i2r_key, r2i_key = _direction_keys(shared_secret, state["msg1"] + msg2)
    tunnel = Tunnel(i2r_key, r2i_key, is_initiator=True)
    return tunnel
