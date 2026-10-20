"""Document signing service (RSA-PSS).

A signature covers a purpose label (e.g. "contract", "invoice") together with the
document, so a signature made for one purpose is not valid for another.
Detached signatures for files are stored next to the file as <path>.sig.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from oqs import KeyEncapsulation, Signature

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def _signed_bytes(document, purpose):
    return b"pq-gate docsign v1|" + purpose.encode() + b"|" + document


def generate_keypair():
    """Return (public_key, private_key) as bytes for a signer."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return public_bytes, private_bytes


def sign_document(private_key, document, purpose="general"):
    """Sign document for the given purpose. Returns the signature bytes."""
    key = serialization.load_pem_private_key(private_key, password=None)
    return key.sign(_signed_bytes(document, purpose), _PSS, hashes.SHA256())


def verify_document(public_key, document, signature, purpose="general"):
    """Return True if signature is valid for document and purpose, else False."""
    key = serialization.load_pem_public_key(public_key)
    try:
        key.verify(signature, _signed_bytes(document, purpose), _PSS, hashes.SHA256())
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

# Example usage (replace with your actual key generation and signing/verification)
if __name__ == "__main__":
    # Generate keypair
    public_key, private_key = generate_keypair()

    # Sign a document
    document = b"This is a test document."
    signature = sign_document(private_key, document)

    # Verify the signature
    verified = verify_document(public_key, document, signature)
    print(f"Signature verified: {verified}")

    # Sign a file
    sign_file("test_file.txt", private_key)

    # Verify the file
    verified = verify_file("test_file.txt", public_key)
    print(f"File verified: {verified}")
