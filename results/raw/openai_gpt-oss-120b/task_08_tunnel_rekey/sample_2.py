"""Encrypted tunnel between two peers, with counter nonces, replay protection and rekeying.

Handshake: ML‑KEM‑768, then HKDF‑SHA256 (bound to both messages) gives one key per direction.
Packets carry an 8‑byte counter that is also the AES‑GCM nonce; old counters are rejected.
rekey() (called on both sides) moves both directions to fresh keys.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import oqs  # liboqs‑python


def _direction_keys(shared_secret: bytes, transcript: bytes):
    """
    Derive two 32‑byte keys (initiator→responder, responder→initiator) from the
    shared secret and the transcript of the handshake.
    """
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"pq-gate tunnel v1" + transcript,
    ).derive(shared_secret)
    return okm[:32], okm[32:]  # i2r, r2i


def _next_key(key: bytes) -> bytes:
    """Derive the next key for a direction (used by rekey)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate tunnel rekey",
    ).derive(key)


class Tunnel:
    """
    Symmetric encrypt/decrypt tunnel.

    The initiator and responder each hold a Tunnel instance after the
    handshake.  ``send`` encrypts with a per‑direction key and a counter‑based
    nonce; ``receive`` decrypts and rejects replayed packets.
    """

    def __init__(self, i2r_key: bytes, r2i_key: bytes, is_initiator: bool):
        # Choose the correct send/receive keys depending on the role.
        self._send_key, self._recv_key = (
            (i2r_key, r2i_key) if is_initiator else (r2i_key, i2r_key)
        )
        self._send_counter = 0
        self._recv_counter = -1

    def send(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` and prepend the 8‑byte counter."""
        counter = self._send_counter
        self._send_counter += 1
        # 4 zero bytes + 8‑byte counter = 12‑byte AES‑GCM nonce.
        nonce = b"\x00" * 4 + counter.to_bytes(8, "big")
        ciphertext = AESGCM(self._send_key).encrypt(nonce, plaintext, None)
        return counter.to_bytes(8, "big") + ciphertext

    def receive(self, packet: bytes) -> bytes:
        """
        Decrypt a packet.  Raises ``ValueError`` on replay, tampering or
        decryption failure.
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
        """Replace both direction keys with fresh ones derived from the old keys."""
        self._send_key = _next_key(self._send_key)
        self._recv_key = _next_key(self._recv_key)
        self._send_counter = 0
        self._recv_counter = -1


def initiator_start():
    """
    Begin the handshake as initiator.

    Returns
    -------
    state : dict
        Contains the secret key and the first handshake message.
    msg1 : bytes
        The public key that will be sent to the responder.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    secret_key = kem.export_secret_key()         # bytes
    return {"secret_key": secret_key, "msg1": public_key}, public_key


def responder_accept(msg1: bytes):
    """
    Process the initiator's first message and produce the responder's reply.

    Parameters
    ----------
    msg1 : bytes
        The initiator's public key (output of ``initiator_start``).

    Returns
    -------
    tunnel : Tunnel
        A Tunnel instance ready for sending/receiving.
    msg2 : bytes
        The ciphertext that must be sent back to the initiator.
    """
    if not isinstance(msg1, (bytes, bytearray)):
        raise ValueError("handshake message must be bytes")

    # Encapsulate using the initiator's public key.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(msg1)

    # Derive direction keys from the shared secret and the transcript.
    i2r_key, r2i_key = _direction_keys(shared_secret, msg1 + ciphertext)

    # Responder is not the initiator.
    tunnel = Tunnel(i2r_key, r2i_key, is_initiator=False)
    return tunnel, ciphertext


def initiator_finish(state: dict, msg2: bytes):
    """
    Complete the handshake on the initiator side.

    Parameters
    ----------
    state : dict
        The state returned by ``initiator_start``.
    msg2 : bytes
        The ciphertext received from the responder.

    Returns
    -------
    tunnel : Tunnel
        A Tunnel instance ready for sending/receiving.
    """
    if not isinstance(msg2, (bytes, bytearray)):
        raise ValueError("handshake message must be bytes")

    # Decapsulate using the initiator's secret key.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=state["secret_key"])
    shared_secret = kem.decap_secret(msg2)

    # Derive direction keys from the shared secret and the transcript.
    i2r_key, r2i_key = _direction_keys(shared_secret, state["msg1"] + msg2)

    # Initiator role.
    return Tunnel(i2r_key, r2i_key, is_initiator=True)
