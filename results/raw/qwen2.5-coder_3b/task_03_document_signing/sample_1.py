"""Document signing service (ML-DSA).

A signature covers a purpose label (e.g. "contract", "invoice") together with the
document, so a signature made for one purpose is not valid for another.
Detached signatures for files are stored next to the file as <path>.sig.
"""
import oqs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ML-DSA-65
sig = oqs.Signature("ML-DSA-65")
public_key = sig.generate_keypair()
secret_key = sig.export_secret_key()
signature = oqs.Signature("ML-DSA-65", secret_key=secret_key).sign(message)
ok = oqs.Signature("ML-DSA-65").verify(message, signature, public_key)  # bool
signature = sig.sign_with_ctx_str(message, context)
ok = oqs.Signature("ML-DSA-65").verify_with_ctx_str(message, signature, context, public_key)

# HKDF (cryptography)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Example usage of HKDF
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"...").derive(input_bytes)
