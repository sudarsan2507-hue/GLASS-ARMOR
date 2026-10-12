"""Smoke test: check that liboqs-python works for ML-KEM-768 and ML-DSA-65."""
import hmac

import oqs

print("liboqs version:", oqs.oqs_version())
print("liboqs-python version:", oqs.oqs_python_version())

# ML-KEM-768: keygen -> encapsulate -> decapsulate, secrets must match
with oqs.KeyEncapsulation("ML-KEM-768") as receiver:
    public_key = receiver.generate_keypair()
    with oqs.KeyEncapsulation("ML-KEM-768") as sender:
        ciphertext, secret_sender = sender.encap_secret(public_key)
    secret_receiver = receiver.decap_secret(ciphertext)
kem_ok = hmac.compare_digest(secret_sender, secret_receiver)
print(f"ML-KEM-768: pk={len(public_key)}B ct={len(ciphertext)}B ss={len(secret_sender)}B "
      f"-> secrets match: {kem_ok}")

# ML-DSA-65: sign -> verify, and a tampered message must be rejected
message = b"PQ-GATE smoke test"
with oqs.Signature("ML-DSA-65") as signer:
    sig_public_key = signer.generate_keypair()
    signature = signer.sign(message)
with oqs.Signature("ML-DSA-65") as verifier:
    valid = verifier.verify(message, signature, sig_public_key)
    tampered = verifier.verify(message + b"!", signature, sig_public_key)
dsa_ok = valid and not tampered
print(f"ML-DSA-65: pk={len(sig_public_key)}B sig={len(signature)}B "
      f"-> valid: {valid}, tampered rejected: {not tampered}")

if not (kem_ok and dsa_ok):
    raise SystemExit("SMOKE TEST FAILED")
print("SMOKE TEST PASSED")
