"""Post‑quantum encrypted tunnel between two peers.

The original implementation used X25519 for the handshake.  This version
replaces the classical Diffie‑Hellman exchange with a KEM based on
ML‑KEM‑768 from liboqs, while preserving the public API:

    state, msg1 = initiator_start()
    responder, msg2 = responder_accept(msg1)
    initiator = initiator_finish(state, msg2)

The rest of the tunnel (AES‑GCM packets, replay protection, re‑keying)
remains unchanged.
"""

from __future__ import annotations

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #
def _direction_keys(shared_secret: bytes, transcript: bytes) -> tuple[bytes, bytes]:
    """
    Derive two 32‑byte keys (initiator→responder and responder→initiator)
    from the KEM shared secret and the transcript of the handshake.
    """
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"pq-gate tunnel v1" + transcript,
    ).derive(shared_secret)
    return okm[:32], okm[32:]


def _next_key(key: bytes) -> bytes:
    """
    Derive a fresh 32‑byte key from the current one (used for re‑keying).
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pq-gate tunnel rekey",
    ).derive(key)


# --------------------------------------------------------------------------- #
# Tunnel class – unchanged apart from the key material source
# --------------------------------------------------------------------------- #
class Tunnel:
    def __init__(self, i2r_key: bytes, r2i_key: bytes, is_initiator: bool):
        """
        i2r_key – key used for traffic from initiator to responder
        r2i_key – key used for traffic from responder to initiator
        is_initiator – True for the initiator side, False for responder
        """
        self._send_key, self._recv_key = (
            (i2r_key, r2i_key) if is_initiator else (r2i_key, i2r_key)
        )
        self._send_counter: int = 0
        self._recv_counter: int = -1

    # --------------------------------------------------------------------- #
    # Packet handling
    # --------------------------------------------------------------------- #
    def send(self, plaintext: bytes) -> bytes:
        """
        Encrypt ``plaintext`` and prepend the 8‑byte packet counter.
        The counter also forms the low 8 bytes of the 12‑byte AES‑GCM nonce.
        """
        counter = self._send_counter
        self._send_counter += 1
        nonce = b"\x00" * 4 + counter.to_bytes(8, "big")
        ciphertext = AESGCM(self._send_key).encrypt(nonce, plaintext, None)
        return counter.to_bytes(8, "big") + ciphertext

    def receive(self, packet: bytes) -> bytes:
        """
        Decrypt a packet.  Raises ``ValueError`` on replay or tampering.
        """
        counter = int.from_bytes(packet[:8], "big")
        if counter <= self._recv_counter:
            raise ValueError("replayed or old packet")
        nonce = b"\x00" * 4 + packet[:8]
        plaintext = AESGCM(self._recv_key).decrypt(nonce, packet[8:], None)
        self._recv_counter = counter
        return plaintext

    # --------------------------------------------------------------------- #
    # Re‑keying
    # --------------------------------------------------------------------- #
    def rekey(self) -> None:
        """Derive fresh send/receive keys and reset counters."""
        self._send_key = _next_key(self._send_key)
        self._recv_key = _next_key(self._recv_key)
        self._send_counter, self._recv_counter = 0, -1


# --------------------------------------------------------------------------- #
# Handshake – now based on ML‑KEM‑768
# --------------------------------------------------------------------------- #
_KEM_ALG = "ML-KEM-768"


def initiator_start() -> tuple[dict, bytes]:
    """
    Generate an ML‑KEM key pair and return the handshake state together
    with the initiator's first message (the public key).

    Returns
    -------
    state : dict
        Contains the secret key (bytes) and the original public key for
        transcript purposes.
    msg1 : bytes
        The initiator's public key, to be sent to the responder.
    """
    # Create a KEM instance and generate a key pair.
    kem = oqs.KeyEncapsulation(_KEM_ALG)
    public_key = kem.generate_keypair()          # bytes
    secret_key = kem.export_secret_key()         # bytes

    state = {
        "secret_key": secret_key,
        "msg1": public_key,
    }
    return state, public_key


def responder_accept(msg1: bytes) -> tuple[Tunnel, bytes]:
    """
    Process the initiator's public key, generate a fresh KEM key pair,
    encapsulate a shared secret to the initiator, and return a
    ``Tunnel`` instance together with the responder's second message
    (the ciphertext).

    Parameters
    ----------
    msg1 : bytes
        Initiator's public key.

    Returns
    -------
    tunnel : Tunnel
        Ready to encrypt/decrypt traffic (responder side).
    msg2 : bytes
        Ciphertext that the initiator will decapsulate to obtain the
        shared secret.
    """
    if not isinstance(msg1, (bytes, bytearray)):
        raise ValueError("bad handshake message")

    # Encapsulate a secret to the initiator's public key.
    encap = oqs.KeyEncapsulation(_KEM_ALG)
    ciphertext, shared_secret = encap.encap_secret(msg1)

    # Derive directional keys using the transcript (msg1 || ciphertext).
    i2r_key, r2i_key = _direction_keys(shared_secret, msg1 + ciphertext)

    # Build the responder's tunnel (is_initiator=False).
    tunnel = Tunnel(i2r_key, r2i_key, is_initiator=False)
    return tunnel, ciphertext


def initiator_finish(state: dict, msg2: bytes) -> Tunnel:
    """
    Complete the handshake on the initiator side.  Decapsulate the
    responder's ciphertext to obtain the shared secret and derive the
    traffic keys.

    Parameters
    ----------
    state : dict
        The object returned by ``initiator_start``.
    msg2 : bytes
        Ciphertext received from the responder.

    Returns
    -------
    tunnel : Tunnel
        Ready to encrypt/decrypt traffic (initiator side).
    """
    if not isinstance(msg2, (bytes, bytearray)):
        raise ValueError("bad handshake message")

    # Re‑create a KEM instance that holds the initiator's secret key.
    kem = oqs.KeyEncapsulation(_KEM_ALG, secret_key=state["secret_key"])
    shared_secret = kem.decap_secret(msg2)

    # Derive directional keys using the same transcript as the responder.
    i2r_key, r2i_key = _direction_keys(shared_secret, state["msg1"] + msg2)

    # Build the initiator's tunnel (is_initiator=True).
    return Tunnel(i2r_key, r2i_key, is_initiator=True)
