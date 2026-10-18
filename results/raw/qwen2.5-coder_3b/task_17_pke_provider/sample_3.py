import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()  # bytes
secret_key = kem.export_secret_key()  # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = kem.encap_secret(public_key)
shared_secret = kem2.decap_secret(ciphertext)  # 32 bytes

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

key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"...").derive(input_bytes)
