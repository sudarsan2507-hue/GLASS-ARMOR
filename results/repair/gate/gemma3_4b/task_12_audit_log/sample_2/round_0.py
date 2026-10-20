"""Tamper-evident audit log (ECDSA P-256 + hash chain).

Each entry is a dict {"seq", "event", "prev", "signature"}. "prev" is the SHA-256 of the
previous entry's signed bytes (64 zeros for the first entry). The signature covers seq,
event and prev, so entries cannot be edited, removed or reordered without detection.
"""
import base64
import hashlib
import json
import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

GENESIS = "0" * 64


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the log writer."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return public_bytes, private_bytes


def _entry_bytes(seq, event, prev):
    return json.dumps({"seq": seq, "event": event, "prev": prev}, sort_keys=True).encode()


def _sign(private_key, data):
    key = serialization.load_pem_private_key(private_key, password=None)
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def _verify(public_key, data, signature):
    try:
        serialization.load_pem_public_key(public_key).verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


class AuditLog:
    """Append-only log writer. `entries` can be stored and later checked with verify_log."""

    def __init__(self, private_key):
        self._private_key = private_key
        self.entries = []
        self._prev = GENESIS

    def append(self, event):
        seq = len(self.entries)
        data = _entry_bytes(seq, event, self._prev)
        entry = {"seq": seq, "event": event, "prev": self._prev,
                 "signature": base64.b64encode(_sign(self._private_key, data)).decode()}
        self.entries.append(entry)
        self._prev = hashlib.sha256(data).hexdigest()
        return entry


def verify_log(public_key, entries):
    """Return True if the whole chain is intact and every signature is valid."""
    prev = GENESIS
    for i, entry in enumerate(entries):
        try:
            data = _entry_bytes(entry["seq"], entry["event"], entry["prev"])
            signature = base64.b64decode(entry["signature"])
        except (KeyError, ValueError):
            return False
        if entry["seq"] != i or entry["prev"] != prev or not _verify(public_key, data, signature):
            return False
        prev = hashlib.sha256(data).hexdigest()
    return True


def main():
    # Example Usage (Illustrative - Replace with your actual setup)
    private_key, _ = generate_keypair()
    log_writer = AuditLog(private_key)

    # Append some entries
    entry1 = log_writer.append("Event 1")
    entry2 = log_writer.append("Event 2")
    entry3 = log_writer.append("Event 3")

    # Verify the log
    is_valid = verify_log(entry1["signature"].encode(), [entry1, entry2, entry3])
    print(f"Log is valid: {is_valid}")

    # Demonstrate ML-KEM and ML-DSA
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key, secret_key = kem.generate_keypair()
    kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
    ciphertext, shared_secret = kem2.encap_secret(public_key)
    print(f"Shared secret: {shared_secret}")
    decap_secret = kem2.decap_secret(ciphertext)
    print(f"Decapsulated shared secret: {decap_secret}")

    sig = oqs.Signature("ML-DSA-65")
    public_key_sig = sig.generate_keypair()
    secret_key_sig = sig.export_secret_key()
    signature = oqs.Signature("ML-DSA-65", secret_key=secret_key_sig).sign(b"test message")
    ok = oqs.Signature("ML-DSA-65").verify(b"test message", signature, public_key_sig)
    print(f"DSA signature verification: {ok}")

    # Demonstrate HKDF
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"...").derive(b"some info")
    print(f"HKDF key: {key}")


if __name__ == "__main__":
    main()
