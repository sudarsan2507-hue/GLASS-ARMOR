"""Document signing service, post-quantum version (ML-DSA-65).

A signature covers a purpose label (e.g. "contract", "invoice") together with the
document: the purpose goes into the ML-DSA context string, so a signature made for
one purpose is not valid for another.
Detached signatures for files are stored next to the file as <path>.sig.
"""
import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

SIG_ALG = "ML-DSA-65"


def _context(purpose):
    return b"pq-gate docsign v1|" + purpose.encode()


def generate_keypair():
    """Return (public_key, private_key) as bytes for a signer."""
    with oqs.Signature(SIG_ALG) as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key


def sign_document(private_key, document, purpose="general"):
    """Sign document for the given purpose. Returns the signature bytes."""
    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:
        return sig.sign_with_ctx_str(document, _context(purpose))


def verify_document(public_key, document, signature, purpose="general"):
    """Return True if signature is valid for document and purpose, else False."""
    try:
        with oqs.Signature(SIG_ALG) as sig:
            if sig.verify_with_ctx_str(document, signature, _context(purpose), public_key):
                return True
    except Exception:
        pass
    return _verify_legacy_rsa(public_key, document, signature, purpose)


def _verify_legacy_rsa(public_key, document, signature, purpose):
    """Signatures made before the migration (RSA-PSS)."""
    try:
        key = serialization.load_pem_public_key(public_key)
        pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
        key.verify(signature, _context(purpose) + b"|" + document, pss, hashes.SHA256())
        return True
    except Exception:
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
