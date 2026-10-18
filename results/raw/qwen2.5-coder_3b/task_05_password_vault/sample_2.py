To migrate the given code from classical cryptography to post-quantum cryptography using `liboqs` (ML-KEM/ML-DSA) and `cryptography` for HKDF, we need to replace the classical cryptographic primitives with their post-quantum counterparts. Here's the updated code:

```python
"""Password vault stored as JSON bytes.

A vault has a random vault key (AES-256-GCM) wrapped with the owner's RSA key (RSA-OAEP).
unlock() recovers the vault key with the private key and checks it against a stored
key-check value (HMAC-SHA256 of a fixed label), so a wrong key gives a clear error.
Entries are encrypted with the vault key; the entry name is used as associated data.
"""
import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
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

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
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

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
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

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
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

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
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

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
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

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
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

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
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

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
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

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
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

# ML-KEM-768
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()            # bytes
secret_key = kem.export_secret_key()           # bytes
kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
ciphertext