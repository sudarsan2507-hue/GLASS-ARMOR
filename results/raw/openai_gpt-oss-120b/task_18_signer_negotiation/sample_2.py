"""Post‑quantum signature handling (ML‑DSA‑65) with the same public API as the
original classical‑crypto version.

The module exposes:
    - SUPPORTED: list of algorithm identifiers (preference order)
    - DEFAULT_ALG: the default algorithm (first in SUPPORTED)
    - get_signer(name): factory returning an object with generate_keypair,
      sign and verify methods
    - negotiate(peer_offers): pick the first mutually supported algorithm
    - seal_envelope(alg, private_key, message): create a signed envelope
    - open_envelope(public_key, envelope): verify and extract the message

All functions keep the same signatures and behaviour as before, but the
underlying cryptography now uses liboqs (ML‑DSA‑65), which is believed to be
secure against quantum adversaries.
"""

import base64
from typing import Tuple, Dict, Any, List

import oqs
from cryptography.exceptions import InvalidSignature  # kept for API compatibility

# --------------------------------------------------------------------------- #
# Configuration – we now only support the post‑quantum ML‑DSA‑65 algorithm.
# --------------------------------------------------------------------------- #
SUPPORTED: List[str] = ["ml-dsa-65"]          # preference order
DEFAULT_ALG: str = SUPPORTED[0]               # default algorithm


# --------------------------------------------------------------------------- #
# Helper – the original code returned PEM‑encoded keys.  For ML‑DSA the keys are
# raw byte strings; they are still opaque to callers, so we simply return the
# bytes produced by liboqs.
# --------------------------------------------------------------------------- #
def _raw_pair(public_key: bytes, secret_key: bytes) -> Tuple[bytes, bytes]:
    """Return a (public_key, private_key) tuple in the same shape as the old
    implementation (both as ``bytes``)."""
    return public_key, secret_key


# --------------------------------------------------------------------------- #
# Post‑quantum signer implementation.
# --------------------------------------------------------------------------- #
class MlDsaSigner:
    """ML‑DSA‑65 signer using liboqs.

    The public API mirrors the original ``EcdsaSigner`` / ``RsaPssSigner``:
        - generate_keypair() → (public_key, private_key)
        - sign(private_key, message) → signature
        - verify(public_key, message, signature) → bool
    """
    name = "ml-dsa-65"

    def __init__(self) -> None:
        # The algorithm name used by liboqs
        self._alg = "ML-DSA-65"

    # ------------------------------------------------------------------- #
    # Key generation
    # ------------------------------------------------------------------- #
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a fresh ML‑DSA‑65 key pair.

        Returns
        -------
        (public_key, private_key) : Tuple[bytes, bytes]
            Both keys are raw byte strings as emitted by liboqs.
        """
        sig = oqs.Signature(self._alg)
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        return _raw_pair(public_key, secret_key)

    # ------------------------------------------------------------------- #
    # Signing
    # ------------------------------------------------------------------- #
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Create a signature over *message* using the supplied private key.

        Parameters
        ----------
        private_key : bytes
            The secret key returned by :meth:`generate_keypair`.
        message : bytes
            The data to be signed.

        Returns
        -------
        signature : bytes
            Raw signature bytes.
        """
        signer = oqs.Signature(self._alg, secret_key=private_key)
        return signer.sign(message)

    # ------------------------------------------------------------------- #
    # Verification
    # ------------------------------------------------------------------- #
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature produced by :meth:`sign`.

        Parameters
        ----------
        public_key : bytes
            The public key returned by :meth:`generate_keypair`.
        message : bytes
            The original signed message.
        signature : bytes
            The signature to verify.

        Returns
        -------
        bool
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        verifier = oqs.Signature(self._alg)
        try:
            return verifier.verify(message, signature, public_key)
        except (InvalidSignature, ValueError):
            # liboqs raises ``ValueError`` for malformed inputs; we map both to
            # a simple ``False`` to keep the original API contract.
            return False


# --------------------------------------------------------------------------- #
# Registry of available signers (only the post‑quantum one now).
# --------------------------------------------------------------------------- #
SIGNERS: Dict[str, Any] = {
    MlDsaSigner.name: MlDsaSigner,
}


def get_signer(name: str):
    """Factory returning a signer instance for *name*.

    Raises
    ------
    ValueError
        If *name* is not present in the ``SIGNERS`` registry.
    """
    if name not in SIGNERS:
        raise ValueError(f"unsupported signature algorithm: {name}")
    return SIGNERS[name]()


# --------------------------------------------------------------------------- #
# Negotiation helper – unchanged semantics.
# --------------------------------------------------------------------------- #
def negotiate(peer_offers: List[str]) -> str:
    """Pick the first algorithm in ``SUPPORTED`` that the peer also offers.

    Parameters
    ----------
    peer_offers : List[str]
        Algorithms advertised by the remote peer.

    Returns
    -------
    str
        The selected algorithm name.

    Raises
    ------
    ValueError
        If there is no overlap between ``SUPPORTED`` and ``peer_offers``.
    """
    for name in SUPPORTED:
        if name in peer_offers:
            return name
    raise ValueError("no common signature algorithm")


# --------------------------------------------------------------------------- #
# Envelope handling – unchanged API, just uses the new signer under the hood.
# --------------------------------------------------------------------------- #
def seal_envelope(alg: str, private_key: bytes, message: bytes) -> Dict[str, str]:
    """Create a signed envelope.

    The envelope is a ``dict`` with three fields:
        - ``alg`` : algorithm identifier (string)
        - ``msg`` : base64‑encoded message payload
        - ``sig`` : base64‑encoded signature over ``alg|message``

    Parameters
    ----------
    alg : str
        Algorithm identifier (must be in ``SUPPORTED``).
    private_key : bytes
        Private key matching *alg*.
    message : bytes
        Payload to protect.

    Returns
    -------
    dict
        The envelope ready for transport.
    """
    signer = get_signer(alg)
    signature = signer.sign(private_key, alg.encode() + b"|" + message)
    return {
        "alg": alg,
        "msg": base64.b64encode(message).decode(),
        "sig": base64.b64encode(signature).decode(),
    }


def open_envelope(public_key: bytes, envelope: Dict[str, Any]) -> bytes:
    """Validate and extract the message from an envelope.

    Raises
    ------
    ValueError
        If the envelope's algorithm is not allowed or the signature is invalid.
    """
    alg = envelope.get("alg")
    if alg not in SUPPORTED:
        raise ValueError("algorithm not allowed")
    message = base64.b64decode(envelope["msg"])
    signature = base64.b64decode(envelope["sig"])
    if not get_signer(alg).verify(public_key, alg.encode() + b"|" + message, signature):
        raise ValueError("bad signature")
    return message
