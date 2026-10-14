"""Pairing a smart-home device with a hub (hybrid X25519 + ML-KEM-768, 6-digit code).
Post-quantum version.

    state, device_hello = device_start(device_id)
    hub_key, hub_hello = hub_respond(device_hello)       # on the hub
    device_key = device_finish(state, hub_hello)         # on the device
Both sides display verification_code(key) and the user confirms they match.
Afterwards the hub authenticates commands to the device with HMAC-SHA256.

device_hello = 1-byte id length | device id | X25519 public key (32) | ML-KEM public key (1184)
hub_hello    = X25519 public key (32) | ML-KEM ciphertext (1088)
The pairing key is HKDF-SHA256 over both shared secrets, bound to both hellos.
"""
import hashlib
import hmac

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALG = "ML-KEM-768"
X_LEN, KEM_PK_LEN, KEM_CT_LEN = 32, 1184, 1088


def _raw(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _pairing_key(classical_secret, pq_secret, transcript):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pq-gate hybrid pairing v1" + transcript).derive(classical_secret + pq_secret)


def device_start(device_id):
    """Start pairing. Returns (device_state, device_hello)."""
    ident = device_id.encode()
    if not 0 < len(ident) < 256:
        raise ValueError("bad device id")
    private_key = X25519PrivateKey.generate()
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_public = kem.generate_keypair()
        kem_secret = kem.export_secret_key()
    hello = bytes([len(ident)]) + ident + _raw(private_key.public_key()) + kem_public
    return {"private_key": private_key, "kem_secret": kem_secret, "hello": hello}, hello


def parse_device_id(device_hello):
    return device_hello[1:1 + device_hello[0]].decode()


def hub_respond(device_hello):
    """Answer a device hello. Returns (pairing_key, hub_hello)."""
    n = device_hello[0] if device_hello else 0
    keys = device_hello[1 + n:]
    if n == 0 or len(keys) != X_LEN + KEM_PK_LEN:
        raise ValueError("bad device hello")
    peer_x, peer_kem = keys[:X_LEN], keys[X_LEN:]
    private_key = X25519PrivateKey.generate()
    classical = private_key.exchange(X25519PublicKey.from_public_bytes(peer_x))
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_ct, pq = kem.encap_secret(peer_kem)
    hub_hello = _raw(private_key.public_key()) + kem_ct
    return _pairing_key(classical, pq, device_hello + hub_hello), hub_hello


def device_finish(state, hub_hello):
    """Finish pairing on the device. Returns pairing_key."""
    if len(hub_hello) != X_LEN + KEM_CT_LEN:
        raise ValueError("bad hub hello")
    peer_x, kem_ct = hub_hello[:X_LEN], hub_hello[X_LEN:]
    classical = state["private_key"].exchange(X25519PublicKey.from_public_bytes(peer_x))
    with oqs.KeyEncapsulation(KEM_ALG, secret_key=state["kem_secret"]) as kem:
        pq = kem.decap_secret(kem_ct)
    return _pairing_key(classical, pq, state["hello"] + hub_hello)


def verification_code(pairing_key):
    """6-digit code shown on both screens."""
    digest = hmac.new(pairing_key, b"verification code", hashlib.sha256).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def sign_command(pairing_key, command):
    """Authenticate a command (bytes) from the hub. Returns a 32-byte tag."""
    return hmac.new(pairing_key, command, hashlib.sha256).digest()


def verify_command(pairing_key, command, tag):
    """Return True if tag is valid for command."""
    return sign_command(pairing_key, command).hex() == tag.hex()
