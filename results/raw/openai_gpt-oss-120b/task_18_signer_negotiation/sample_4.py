"""Post‑quantum signature handling (ML‑DSA) with the same public API as the original
classical implementation.

The module provides:
* SUPPORTED – list of algorithm identifiers we can use (currently only ML‑DSA‑65)
* DEFAULT_ALG – the preferred algorithm
* get_signer(name) – obtain a signer instance
* negotiate(peer_offers) – pick the first mutually supported algorithm
* seal_envelope(alg, private_key, message) – create a signed envelope
* open_envelope(public_key, envelope) – verify and extract the message

All functions keep the same signatures as the original version, so existing
tests that import and use them continue to work.
"""

import base64
from typing import Tuple, Dict, Any, List

import oqs  # liboqs‑python

# --------------------------------------------------------------------------- #
# Configuration – we now prefer the post‑quantum ML‑DSA‑65 signature algorithm.
# --------------------------------------------------------------------------- #
SUPPORTED: List[str] = ["ml-dsa-65"]          # Preference order
DEFAULT_ALG: str = SUPPORTED[0]               # The default algorithm


# --------------------------------------------------------------------------- #
# Helper – a simple container for a public / private key pair.
# The keys are raw bytes as returned by liboqs; they are **not** PEM encoded.
# --------------------------------------------------------------------------- #
def _raw_pair(private_key: bytes) -> Tuple[bytes, bytes]:
    """Return (public_key, private_key) given a private key.

    For liboqs the public key can be derived from the private key via the
    Signature object, but the generate_keypair method already returns both.
    This helper exists only to keep the original function signature shape.
    """
    # The private_key is actually the secret key; the public key must be
    # supplied separately by the caller.  This function is retained for API
    # compatibility but is not used internally.
    raise NotImplementedError("Raw key pairs are generated directly by the signer.")


# --------------------------------------------------------------------------- #
# Post‑quantum signer implementation using ML‑DSA‑65.
# --------------------------------------------------------------------------- #
class MlDsaSigner:
    """ML‑DSA‑65 signer using liboqs.

    The public and private keys are raw byte strings as returned by liboqs.
    """
    name = "ml-dsa-65"

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a (public_key, private_key) pair.

        Returns:
            Tuple[bytes, bytes]: (public_key, secret_key)
        """
        sig = oqs.Signature(self.name)
        public_key = sig.generate_keypair()          # bytes
        secret_key = sig.export_secret_key()         # bytes
        return public_key, secret_key

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Create a signature over *message* using the supplied private key.

        Args:
            private_key: The secret key (bytes) obtained from generate_keypair().
            message: The message to sign.

        Returns:
            bytes: The signature.
        """
        signer = oqs.Signature(self.name, secret_key=private_key)
        return signer.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature.

        Args:
            public_key: The public key (bytes) obtained from generate_keypair().
            message: The original message.
            signature: The signature to verify.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        verifier = oqs.Signature(self.name)
        return verifier.verify(message, signature, public_key)


# --------------------------------------------------------------------------- #
# Registry of available signers.
# --------------------------------------------------------------------------- #
SIGNERS = {
    MlDsaSigner.name: MlDsaSigner,
}


# --------------------------------------------------------------------------- #
# Public helper functions (unchanged API).
# --------------------------------------------------------------------------- #
def get_signer(name: str):
    """Return an instantiated signer for *name*.

    Raises:
        ValueError: If the algorithm is not supported.
    """
    if name not in SIGNERS:
        raise ValueError(f"unsupported signature algorithm: {name}")
    return SIGNERS[name]()


def negotiate(peer_offers: List[str]) -> str:
    """Pick the first algorithm in SUPPORTED that the peer also offers.

    Args:
        peer_offers: List of algorithm identifiers advertised by the peer.

    Returns:
        The chosen algorithm name.

    Raises:
        ValueError: If there is no common algorithm.
    """
    for name in SUPPORTED:
        if name in peer_offers:
            return name
    raise ValueError("no common signature algorithm")


def seal_envelope(alg: str, private_key: bytes, message: bytes) -> Dict[str, Any]:
    """Create a signed envelope.

    The envelope format matches the original implementation:
        {
            "alg": "<algorithm>",
            "msg": "<base64‑encoded message>",
            "sig": "<base64‑encoded signature>"
        }

    Args:
        alg: Algorithm identifier (must be in SUPPORTED).
        private_key: Private key bytes for the chosen algorithm.
        message: Raw message bytes to protect.

    Returns:
        dict: The envelope ready for transmission.
    """
    signer = get_signer(alg)
    # The signed payload includes the algorithm name to bind the signature
    # to the chosen algorithm, mirroring the original behaviour.
    payload = alg.encode() + b"|" + message
    signature = signer.sign(private_key, payload)
    return {
        "alg": alg,
        "msg": base64.b64encode(message).decode(),
        "sig": base64.b64encode(signature).decode(),
    }


def open_envelope(public_key: bytes, envelope: Dict[str, Any]) -> bytes:
    """Validate an envelope and return the contained message.

    Raises:
        ValueError: If the algorithm is not allowed or the signature is invalid.
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
