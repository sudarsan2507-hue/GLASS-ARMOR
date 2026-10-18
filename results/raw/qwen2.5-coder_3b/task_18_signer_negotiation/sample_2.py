import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

SUPPORTED = ["ml-kem-768", "ml-dsa-65"]  # our preference order
DEFAULT_ALG = SUPPORTED[0]


def _pem_pair(private_key):
    return (private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo),
            private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))


class MlKem768:
    name = "ml-kem-768"

    def generate_keypair(self):
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        public_key = kem.generate_keypair()  # bytes
        secret_key = kem.export_secret_key()  # bytes
        kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
        ciphertext, shared_secret = kem2.encap_secret(public_key)
        shared_secret = kem2.decap_secret(ciphertext)  # 32 bytes
        return public_key, shared_secret

    def export_secret_key(self, secret_key):
        return secret_key


class MlDsa65:
    name = "ml-dsa-65"

    def generate_keypair(self):
        sig = oqs.Signature("ML-DSA-65")
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        signature = sig.sign(message)
        ok = sig.verify(message, signature, public_key)  # bool
        return public_key, secret_key

    def export_secret_key(self, secret_key):
        return secret_key


SIGNERS = {MlKem768.name: MlKem768, MlDsa65.name: MlDsa65}


def get_signer(name):
    if name not in SIGNERS:
        raise ValueError(f"unsupported signature algorithm: {name}")
    return SIGNERS[name]()


def negotiate(peer_offers):
    """Pick the first algorithm in SUPPORTED that the peer also offers."""
    for name in SUPPORTED:
        if name in peer_offers:
            return name
    raise ValueError("no common signature algorithm")


def seal_envelope(alg, private_key, message):
    signature = get_signer(alg).sign(private_key, alg.encode() + b"|" + message)
    return {"alg": alg, "msg": base64.b64encode(message).decode(), "sig": base64.b64encode(signature).decode()}


def open_envelope(public_key, envelope):
    """Return the message bytes. Raises ValueError if the algorithm or signature is not acceptable."""
    alg = envelope.get("alg")
    if alg not in SUPPORTED:
        raise ValueError("algorithm not allowed")
    message = base64.b64decode(envelope["msg"])
    if not get_signer(alg).verify(public_key, alg.encode() + b"|" + message, base64.b64decode(envelope["sig"])):
        raise ValueError("bad signature")
    return message
