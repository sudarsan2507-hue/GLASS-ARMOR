"""Document signing service (ML-KEM / ML-DSA).

A signature covers a purpose label (e.g. "contract", "invoice") together with the
document, so a signature made for one purpose is not valid for another.
Detached signatures for files are stored next to the file as <path>.sig.
"""
from oqs import KeyEncapsulation, Signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

def _signed_bytes(document, purpose):
    return b"pq-gate docsign v1|" + purpose.encode() + b"|" + document

def generate_keypair():
    """Return (public_key, private_key) as bytes for a signer."""
    kem = KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()            # bytes
    secret_key = kem.export_secret_key()           # bytes
    return public_key, secret_key

def sign_document(private_key, document, purpose="general"):
    """Sign document for the given purpose. Returns the signature bytes."""
    sig = Signature("ML-DSA-65")
    return sig.sign(_signed_bytes(document, purpose), private_key, hashes.SHA256())

def verify_document(public_key, document, signature, purpose="general"):
    """Return True if signature is valid for document and purpose, else False."""
    sig = Signature("ML-DSA-65")
    try:
        sig.verify(signature, _signed_bytes(document, purpose), public_key, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False

def sign_file(path, private_key, purpose="general"):
    """Sign the file at path and write the signature to <path>.sig."""
    with open(path, "rb") as f:
        signature = sign_document(private_key, f.read(), purpose)
    with open(path + ".sig", "wb") as f:
        f.write(signature)

def verify_file(path, public_key, purpose="general"):
    """Check <path>.sig against the file at path. Returns True or False."""
    with open(path, "rb") as f:
        document = f.read()
    with open(path + ".sig", "rb") as f:
        signature = f.read()
    return verify_document(public_key, document, signature, purpose)
