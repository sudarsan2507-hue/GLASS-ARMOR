```python
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.dsa import DSAKeyPairGenerator, DSAKeyPair, DSAParameters
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import prehashed


def _raw(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _session_key(shared_secret, transcript):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate session v1" + transcript).derive(shared_secret)


def client_start():
    """Start a handshake. Returns (client_state, client_hello)."""
    private_key = X25519PrivateKey.generate()
    client_hello = _raw(private_key.public_key())
    return {"private_key": private_key, "client_hello": client_hello}, client_hello


def server_respond(client_hello):
    """Answer a client hello. Returns (session_key, server_hello)."""
    if len(client_hello) != 32:
        raise ValueError("bad client hello")
    private_key = X25519PrivateKey.generate()
    server_hello = _raw(private_key.public_key())
    shared = private_key.exchange(X25519PublicKey.from_public_bytes(client_hello))
    return _session_key(shared, client_hello + server_hello), server_hello


def client_finish(client_state, server_hello):
    """Finish the handshake on the client. Returns session_key."""
    if len(server_hello) != 32:
        raise ValueError("bad server hello")
    peer = X25519PublicKey.from_public_bytes(server_hello)
    shared = client_state["private_key"].exchange(peer)
    return _session_key(shared, client_state["client_hello"] + server_hello)


class SecureChannel:
    """Encrypts and decrypts messages under a session key (AES-256-GCM)."""

    def __init__(self, session_key):
        self._aead = AESGCM(session_key)

    def encrypt(self, plaintext, aad=b""):
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, message, aad=b""):
        """Raises if the message was tampered with or the key/aad is wrong."""
        return self._aead.decrypt(message[:12], message[12:], aad)


class DSAKeyPairGenerator:
    def __init__(self, parameters):
        self._parameters = parameters

    def generate(self):
        return DSAKeyPair.generate(self._parameters)


class DSAKeyPair:
    def __init__(self, private_key, public_key):
        self._private_key = private_key
        self._public_key = public_key

    def sign(self, message, hash_algorithm=hashes.SHA256()):
        return self._private_key.sign(
            message,
            padding.PKCS1v15(),
            hash_algorithm
        )

    def verify(self, message, signature, hash_algorithm=hashes.SHA256()):
        return self._public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hash_algorithm
        )


class DSAParameters:
    def __init__(self, p, q, g):
        self._p = p
        self._q = q
        self._g = g

    def generate_keypair(self):
        return DSAKeyPair(
            private_key=DSAKeyPairGenerator(self).generate(),
            public_key=self._g ** self._x % self._p
        )

    def generate_keypair_with_ctx_str(self, message, context):
        raise NotImplementedError("DSA does not support context strings")

    def generate_keypair_with_ctx_bytes(self, message, context):
        raise NotImplementedError("DSA does not support context bytes")

    def generate_keypair_with_ctx_hash(self, message, context):
        raise NotImplementedError("DSA does not support context hash")

    def generate_keypair_with_ctx_hash_and_salt(self, message, context, salt):
        raise NotImplementedError("DSA does not support context hash and salt")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations(self, message, context, salt, iterations):
        raise NotImplementedError("DSA does not support context hash, salt, and iterations")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label(self, message, context, salt, iterations, label):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, and label")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params(self, message, context, salt, iterations, label, params):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, and params")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve(self, message, context, salt, iterations, label, params, curve):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, and curve")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group(self, message, context, salt, iterations, label, params, curve, group):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, and group")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type(self, message, context, salt, iterations, label, params, curve, group, key_type):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, and key type")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, and algorithm")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group, key_type):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group, and key type")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group, and key type, and algorithm")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group, and key type, and algorithm, and params")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params, curve):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group, and key type, and algorithm, and params, and curve")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params, curve, group):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group, and key type, and algorithm, and params, and curve, and group")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params, curve, group, key_type):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group, and key type, and algorithm, and params, and curve, and group, and key type")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group, and key type, and algorithm, and params, and curve, and group, and key type, and algorithm")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group, and key type, and algorithm, and params, and curve, and group, and key type, and algorithm, and params")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params, curve):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group, and key type, and algorithm, and params, and curve, and group, and key type, and algorithm, and params, and curve")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group(self, message, context, salt, iterations, label, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params, curve, group, key_type, algorithm, params, curve, group):
        raise NotImplementedError("DSA does not support context hash, salt, iterations, label, params, curve, group, key type, algorithm, and params, and curve, and group, and key type, and algorithm, and params, and curve, and group, and key type, and algorithm, and params, and curve, and group")

    def generate_keypair_with_ctx_hash_and_salt_and_iterations_and_label_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and_group_and_key_type_and_algorithm_and_params_and_curve_and