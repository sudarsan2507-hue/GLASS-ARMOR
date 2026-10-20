"""Post‑quantum signature handling (ML‑DSA‑65) with the same public API as the
original classical‑crypto version.

The module provides:
* `get_signer(name)` – obtain a signer instance.
* `negotiate(peer_offers)` – pick the first mutually supported algorithm.
* `seal_envelope(alg, private_key, message)` – sign and package a message.
* `open_envelope(public_key, envelope)` – verify and unpack a message.

All functions keep the original signatures so existing tests continue to work.
"""

import base64
from typing import Tuple, Dict, Any, List

import oqs  # liboqs‑python

# --------------------------------------------------------------------------- #
# Supported algorithms – we now only expose the post‑quantum ML‑DSA‑65.
# The order defines our preference when negotiating with a peer.
# --------------------------------------------------------------------------- #
SUPPORTED: List[str] = ["ml-dsa-65"]
DEFAULT_ALG: str = SUPPORTED[0]


# --------------------------------------------------------------------------- #
# Helper – the original code returned PEM‑encoded keys.  For ML‑DSA the keys are
# raw bytes, which is sufficient for the public API (the caller treats them as
# opaque blobs).  The helper is kept for compatibility but is no longer used.
# --------------------------------------------------------------------------- #
def _pem_pair(_: Any) -> Tuple[bytes, bytes]:  # pragma: no cover
    raise NotImplementedError(
        "PEM encoding is not applicable to ML‑DSA keys; use raw bytes."
    )


# --------------------------------------------------------------------------- #
# ML‑DSA‑65 signer implementation
# --------------------------------------------------------------------------- #
class MlDsaSigner:
    """Post‑quantum signer based on the ML‑DSA‑65 algorithm."""

    name = "ml-dsa-65"

    def __init__(self) -> None:
        # The algorithm identifier used by liboqs.
        self._alg = "ML-DSA-65"

    # --------------------------------------------------------------------- #
    # Key generation
    # --------------------------------------------------------------------- #
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a fresh ML‑DSA‑65 key pair.

        Returns
        -------
        (public_key, private_key) : Tuple[bytes, bytes]
            * ``public_key`` – bytes that can be shared with a verifier.
            * ``private_key`` – bytes that must be kept secret and used for
              signing.
        """
        signer = oqs.Signature(self._alg)
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        return public_key, private_key

    # --------------------------------------------------------------------- #
    # Signing
    # --------------------------------------------------------------------- #
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Produce a signature for ``message`` using the supplied private key.

        Parameters
        ----------
        private_key : bytes
            The secret key returned by :meth:`generate_keypair`.
        message : bytes
            The data to be signed.

        Returns
        -------
        signature : bytes
            The ML‑DSA‑65 signature.
        """
        signer = oqs.Signature(self._alg, secret_key=private_key)
        return signer.sign(message)

    # --------------------------------------------------------------------- #
    # Verification
    # --------------------------------------------------------------------- #
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature.

        Parameters
        ----------
        public_key : bytes
            The public key returned by :meth:`generate_keypair`.
        message : bytes
            The original signed data.
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
        except Exception:  # liboqs may raise generic exceptions on failure
            return False


# --------------------------------------------------------------------------- #
# Registry of available signers (kept as a dict for easy lookup)
# --------------------------------------------------------------------------- #
SIGNERS: Dict[str, Any] = {"ml-dsa-65": MlDsaSigner}


def get_signer(name: str) -> Any:
    """
    Retrieve a signer instance by name.

    Parameters
    ----------
    name : str
        The algorithm identifier (must be present in ``SIGNERS``).

    Returns
    -------
    signer : object
        An instance providing ``generate_keypair``, ``sign`` and ``verify``.
    """
    if name not in SIGNERS:
        raise ValueError(f"unsupported signature algorithm: {name}")
    return SIGNERS[name]()


def negotiate(peer_offers: List[str]) -> str:
    """
    Choose the first algorithm we support that also appears in the peer's list.

    Parameters
    ----------
    peer_offers : List[str]
        Algorithms advertised by the peer.

    Returns
    -------
    str
        The selected algorithm name.

    Raises
    ------
    ValueError
        If there is no overlap between our ``SUPPORTED`` list and ``peer_offers``.
    """
    for name in SUPPORTED:
        if name in peer_offers:
            return name
    raise ValueError("no common signature algorithm")


def seal_envelope(alg: str, private_key: bytes, message: bytes) -> Dict[str, str]:
    """
    Sign ``message`` with ``private_key`` and package it together with the
    algorithm identifier.

    The envelope format matches the original implementation:
    ``{"alg": ..., "msg": base64(message), "sig": base64(signature)}``.

    Parameters
    ----------
    alg : str
        The algorithm name (must be one we support).
    private_key : bytes
        Private key for signing.
    message : bytes
        Plaintext payload.

    Returns
    -------
    dict
        The envelope ready for transport.
    """
    signer = get_signer(alg)
    # The signed payload includes the algorithm name to bind the signature to it.
    payload = alg.encode() + b"|" + message
    signature = signer.sign(private_key, payload)
    return {
        "alg": alg,
        "msg": base64.b64encode(message).decode(),
        "sig": base64.b64encode(signature).decode(),
    }


def open_envelope(public_key: bytes, envelope: Dict[str, str]) -> bytes:
    """
    Verify the envelope and return the original message.

    Parameters
    ----------
    public_key : bytes
        The public key corresponding to the private key used for signing.
    envelope : dict
        The envelope produced by :func:`seal_envelope`.

    Returns
    -------
    bytes
        The original message payload.

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
    payload = alg.encode() + b"|" + message

    if not get_signer(alg).verify(public_key, payload, signature):
        raise ValueError("bad signature")
    return message
