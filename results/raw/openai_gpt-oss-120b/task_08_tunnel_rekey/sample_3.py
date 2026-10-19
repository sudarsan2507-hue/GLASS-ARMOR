"""Encrypted tunnel between two peers, using post‑quantum ML‑KEM‑768 for the
handshake.  The public API (initiator_start, responder_accept,
initiator_finish, Tunnel) is unchanged so existing tests continue to work.

Handshake:
    1. Initiator generates a KEM keypair and sends the public key (msg1).
    2. Responder encapsulates a shared secret to the initiator's public key,
       sending the ciphertext (msg2).
    3. Both sides derive direction‑specific keys from the shared secret and
       the transcript (msg1 || msg2) via HKDF‑SHA256.

Packets carry an 8‑byte counter that is also the AES‑GCM nonce; old counters
are rejected.  rekey() (called on both sides) moves both directions to fresh
keys.
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
    """Derive the next key for a rekey operation."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate tunnel rekey",
    ).derive(key)


class Tunnel:
    """
    Symmetric encrypt/decrypt tunnel with replay protection and explicit
    rekeying.  The same class works for both initiator and responder – the
    constructor receives the correct send/receive keys based on the role.
    """

    def __init__(self, i2r_key: bytes, r2i_key: bytes, is_initiator: bool):
        # Choose the correct orientation of the keys.
        self._send_key, self._recv_key = (
            (i2r_key, r2i_key) if is_initiator else (r2i_key, i2r_key)
        )
        self._send_counter = 0
        self._recv_counter = -1

    def send(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` and prepend the 8‑byte counter."""
        counter = self._send_counter
        self._send_counter += 1
        # 4 zero bytes + 8‑byte counter = 12‑byte nonce for AES‑GCM.
        nonce = b"\x00" * 4 + counter.to_bytes(8, "big")
        ciphertext = AESGCM(self._send_key).encrypt(nonce, plaintext, None)
        return counter.to_bytes(8, "big") + ciphertext

    def receive(self, packet: bytes) -> bytes:
        """
        Decrypt a packet.  Raises ``ValueError`` on replay, tampering or
        authentication failure.
        """
        counter = int.from_bytes(packet[:8], "big")
        if counter <= self._recv_counter:
            raise ValueError("replayed or old packet")
        nonce = b"\x00" * 4 + packet[:8]
        plaintext = AESGCM(self._recv_key).decrypt(nonce, packet[8:], None)
        self._recv_counter = counter
        return plaintext

    def rekey(self):
        """Replace both send and receive keys with fresh ones derived from the
        current keys.  Counters are reset."""
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
        Opaque state that must be passed to ``initiator_finish``.
    msg1 : bytes
        The initiator's KEM public key to be sent to the responder.
    """
    # Generate a fresh ML‑KEM‑768 keypair.
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # bytes
    secret_key = kem.export_secret_key()         # bytes (private part)

    # Store only what we need for the later decapsulation.
    state = {
        "secret_key": secret_key,
        "msg1": public_key,
    }
    return state, public_key


def responder_accept(msg1: bytes):
    """
    Process the initiator's message and produce a response.

    Parameters
    ----------
    msg1 : bytes
        Initiator's KEM public key.

    Returns
    -------
    tunnel : Tunnel
        Ready to encrypt/decrypt traffic.
    msg2 : bytes
        Ciphertext containing the encapsulated shared secret.
    """
    if not isinstance(msg1, (bytes, bytearray)):
        raise ValueError("msg1 must be bytes")
    # Encapsulate a shared secret to the initiator's public key.
    ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(
        msg1
    )
    # Derive direction‑specific keys from the shared secret and transcript.
    i2r_key, r2i_key = _direction_keys(shared_secret, msg1 + ciphertext)
    tunnel = Tunnel(i2r_key, r2i_key, is_initiator=False)
    return tunnel, ciphertext


def initiator_finish(state: dict, msg2: bytes):
    """
    Complete the handshake on the initiator side.

    Parameters
    ----------
    state : dict
        The opaque state returned by ``initiator_start``.
    msg2 : bytes
        Ciphertext received from the responder.

    Returns
    -------
    tunnel : Tunnel
        Ready to encrypt/decrypt traffic.
    """
    if not isinstance(msg2, (bytes, bytearray)):
        raise ValueError("msg2 must be bytes")
    secret_key = state.get("secret_key")
    if secret_key is None:
        raise ValueError("invalid initiator state")
    # Decapsulate to obtain the shared secret.
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
    shared_secret = kem.decap_secret(msg2)
    # Derive the direction‑specific keys.
    i2r_key, r2i_key = _direction_keys(
        shared_secret, state["msg1"] + msg2
    )
    return Tunnel(i2r_key, r2i_key, is_initiator=True)
