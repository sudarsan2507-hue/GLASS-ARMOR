"""Post‑quantum signature handling (ML‑DSA‑65) with the same public API as the
original classical‑crypto version.

The module provides:
* `SUPPORTED` – ordered list of algorithms we are willing to use.
* `DEFAULT_ALG` – the first algorithm in `SUPPORTED`.
* `get_signer(name)` – factory returning an object with `generate_keypair`,
  `sign` and `verify` methods.
* `negotiate(peer_offers)` – pick the first mutually supported algorithm.
* `seal_envelope(alg, private_key, message)` – create a signed envelope.
* `open_envelope(public_key, envelope)` – verify and extract the message.

All cryptographic operations are performed with liboqs (ML‑DSA‑65).  Keys are
returned as raw bytes (the format used by liboqs) rather than PEM strings,
but the surrounding code only treats them as opaque blobs, so the change is
transparent to callers and existing tests.
"""

import base64
from typing import Tuple, Dict, Any, List

import oqs
from cryptography.exceptions import InvalidSignature  # kept for API compatibility

# --------------------------------------------------------------------------- #
# Public configuration
# --------------------------------------------------------------------------- #
SUPPORTED: List[str] = ["ml-dsa-65"]          # preference order (post‑quantum)
DEFAULT_ALG: str = SUPPORTED[0]


# --------------------------------------------------------------------------- #
# Helper – no PEM handling any more; keys are raw bytes from liboqs
# --------------------------------------------------------------------------- #
def _raw_pair(public_key: bytes, private_key: bytes) -> Tuple[bytes, bytes]:
    """Return a (public_key, private_key) tuple in the same shape as the old
    `_pem_pair` helper.  The values are raw bytes, not PEM‑encoded data.
    """
    return public_key, private_key


# --------------------------------------------------------------------------- #
# Signer implementation using ML‑DSA‑65
# --------------------------------------------------------------------------- #
class MLDSASigner:
    """Post‑quantum signature algorithm based on liboqs' ML‑DSA‑65."""
    name = "ml-dsa-65"

    def __init__(self) -> None:
        # The algorithm name used by liboqs is case‑sensitive.
        self._alg_name = "ML-DSA-65"

    # ------------------------------------------------------------------- #
    # Key generation
    # ------------------------------------------------------------------- #
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a public / private key pair.

        Returns
        -------
        (public_key, private_key) : Tuple[bytes, bytes]
            Both keys are raw byte strings as defined by liboqs.
        """
        sig = oqs.Signature(self._alg_name)
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return _raw_pair(public_key, private_key)

    # ------------------------------------------------------------------- #
    # Signing
    # ------------------------------------------------------------------- #
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Create a signature for *message* using the supplied private key.

        Parameters
        ----------
        private_key : bytes
            The private key previously obtained from ``generate_keypair``.
        message : bytes
            The data to be signed.

        Returns
        -------
        signature : bytes
            The raw signature bytes.
        """
        signer = oqs.Signature(self._alg_name, secret_key=private_key)
        return signer.sign(message)

    # ------------------------------------------------------------------- #
    # Verification
    # ------------------------------------------------------------------- #
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature.

        Parameters
        ----------
        public_key : bytes
            The public key corresponding to the private key used for signing.
        message : bytes
            The original signed message.
        signature : bytes
            The signature to verify.

        Returns
        -------
        bool
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        verifier = oqs.Signature(self._alg_name)
        try:
            return verifier.verify(message, signature, public_key)
        except Exception:  # liboqs raises generic exceptions on failure
            return False


# --------------------------------------------------------------------------- #
# Registry of available signers
# --------------------------------------------------------------------------- #
SIGNERS: Dict[str, Any] = {
    MLDSASigner.name: MLDSASigner,
}


# --------------------------------------------------------------------------- #
# Public factory / negotiation helpers
# --------------------------------------------------------------------------- #
def get_signer(name: str):
    """Return an instantiated signer object for *name*.

    Raises
    ------
    ValueError
        If *name* is not present in the ``SIGNERS`` registry.
    """
    if name not in SIGNERS:
        raise ValueError(f"unsupported signature algorithm: {name}")
    return SIGNERS[name]()


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
        If there is no overlap between our preferences and the peer's offers.
    """
    for name in SUPPORTED:
        if name in peer_offers:
            return name
    raise ValueError("no common signature algorithm")


# --------------------------------------------------------------------------- #
# Envelope handling (unchanged API)
# --------------------------------------------------------------------------- #
def seal_envelope(alg: str, private_key: bytes, message: bytes) -> Dict[str, str]:
    """Create a signed envelope.

    The envelope is a ``dict`` with three fields:
    * ``alg`` – the algorithm identifier,
    * ``msg`` – base64‑encoded payload,
    * ``sig`` – base64‑encoded signature over ``alg|msg``.
    """
    signer = get_signer(alg)
    signature = signer.sign(private_key, alg.encode() + b"|" + message)
    return {
        "alg": alg,
        "msg": base64.b64encode(message).decode(),
        "sig": base64.b64encode(signature).decode(),
    }


def open_envelope(public_key: bytes, envelope: Dict[str, Any]) -> bytes:
    """Validate an envelope and return the original message.

    Raises
    ------
    ValueError
        If the algorithm is not allowed or the signature verification fails.
    """
    alg = envelope.get("alg")
    if alg not in SUPPORTED:
        raise ValueError("algorithm not allowed")
    message = base64.b64decode(envelope["msg"])
    signature = base64.b64decode(envelope["sig"])
    signer = get_signer(alg)
    if not signer.verify(public_key, alg.encode() + b"|" + message, signature):
        raise ValueError("bad signature")
    return message
