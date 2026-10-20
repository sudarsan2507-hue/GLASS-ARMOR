"""Post‑quantum signature handling (ML‑DSA‑65) with the same public API as the
original classical implementation.

The module provides:
* `get_signer(name)` – returns a signer object for the requested algorithm.
* `negotiate(peer_offers)` – picks the first mutually supported algorithm.
* `seal_envelope(alg, private_key, message)` – creates a signed envelope.
* `open_envelope(public_key, envelope)` – verifies and extracts the message.

The implementation now uses liboqs (ML‑DSA‑65) for signatures while keeping
the function signatures and return types compatible with the original code.
"""

import base64

import oqs
from cryptography.exceptions import InvalidSignature

# --------------------------------------------------------------------------- #
# Configuration – we now prefer the post‑quantum algorithm.
# --------------------------------------------------------------------------- #
SUPPORTED = ["ml-dsa-65"]          # Preference order (can be extended later)
DEFAULT_ALG = SUPPORTED[0]        # The default algorithm used by the library


# --------------------------------------------------------------------------- #
# Helper – no PEM handling is needed for liboqs; keys are raw bytes.
# --------------------------------------------------------------------------- #
def _bytes_pair(public_key: bytes, private_key: bytes):
    """Return a tuple (public_key, private_key) – both are raw bytes."""
    return public_key, private_key


# --------------------------------------------------------------------------- #
# ML‑DSA‑65 signer implementation.
# --------------------------------------------------------------------------- #
class MLDsaSigner:
    """Post‑quantum signer based on liboqs ML‑DSA‑65.

    The public and private keys are raw byte strings returned by liboqs.
    """

    name = "ml-dsa-65"

    def generate_keypair(self):
        """Generate a new ML‑DSA‑65 key pair.

        Returns
        -------
        (bytes, bytes)
            A tuple ``(public_key, private_key)`` where both elements are raw
            byte strings.
        """
        sig = oqs.Signature(self.name.upper())
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return _bytes_pair(public_key, private_key)

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Create a signature over *message* using the supplied private key.

        Parameters
        ----------
        private_key : bytes
            The private key returned by :meth:`generate_keypair`.
        message : bytes
            The data to be signed.

        Returns
        -------
        bytes
            The raw signature.
        """
        signer = oqs.Signature(self.name.upper(), secret_key=private_key)
        return signer.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature.

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
        verifier = oqs.Signature(self.name.upper())
        try:
            return verifier.verify(message, signature, public_key)
        except Exception:  # liboqs may raise generic exceptions on failure
            return False


# --------------------------------------------------------------------------- #
# Registry of available signers.
# --------------------------------------------------------------------------- #
SIGNERS = {
    MLDsaSigner.name: MLDsaSigner,
    # Future classical signers could be added here for backward compatibility.
}


def get_signer(name: str):
    """Return an instantiated signer for *name*.

    Raises
    ------
    ValueError
        If the requested algorithm is not in the registry.
    """
    if name not in SIGNERS:
        raise ValueError(f"unsupported signature algorithm: {name}")
    return SIGNERS[name]()


def negotiate(peer_offers):
    """Pick the first algorithm in ``SUPPORTED`` that the peer also offers.

    Parameters
    ----------
    peer_offers : iterable[str]
        Algorithms advertised by the peer.

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


def seal_envelope(alg: str, private_key: bytes, message: bytes) -> dict:
    """Create a signed envelope.

    The envelope format is compatible with the original implementation:
    ``{"alg": ..., "msg": ..., "sig": ...}`` where ``msg`` and ``sig`` are
    base64‑encoded strings.

    Parameters
    ----------
    alg : str
        The algorithm name (must be one of ``SUPPORTED``).
    private_key : bytes
        Private key for the chosen algorithm.
    message : bytes
        The payload to protect.

    Returns
    -------
    dict
        The envelope ready for transport.
    """
    signer = get_signer(alg)
    # The signed data includes the algorithm name to bind the signature to it.
    signed_data = alg.encode() + b"|" + message
    signature = signer.sign(private_key, signed_data)
    return {
        "alg": alg,
        "msg": base64.b64encode(message).decode(),
        "sig": base64.b64encode(signature).decode(),
    }


def open_envelope(public_key: bytes, envelope: dict) -> bytes:
    """Validate an envelope and return the contained message.

    Parameters
    ----------
    public_key : bytes
        Public key corresponding to the private key that signed the envelope.
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
    signed_data = alg.encode() + b"|" + message
    if not get_signer(alg).verify(public_key, signed_data, signature):
        raise ValueError("bad signature")
    return message
