"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F1: KEM shared secret used directly as the AES key, no KDF
    "b1_F1_raw_secret_key": [
        ("from cryptography.hazmat.primitives import hashes\n", ""),
        ("from cryptography.hazmat.primitives.kdf.hkdf import HKDF\n", ""),
        ("def _derive_kek(shared_secret):\n"
         "    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,\n"
         "                info=b\"pq-gate file key wrap v1\").derive(shared_secret)\n\n\n", ""),
        ("AESGCM(_derive_kek(shared_secret))", "AESGCM(shared_secret)"),
    ],
    # F3: legacy RSA-OAEP path still reachable when a PEM key is passed in
    "b2_F3_rsa_fallback": [
        ("from cryptography.hazmat.primitives import hashes\n",
         "from cryptography.hazmat.primitives import hashes, serialization\n"
         "from cryptography.hazmat.primitives.asymmetric import padding\n"),
        ("KEM_CT_LEN = 1088\n",
         "KEM_CT_LEN = 1088\n"
         "_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),\n"
         "                     algorithm=hashes.SHA256(), label=None)\n"),
        ('    """Wrap a data key for the owner of public_key."""\n',
         '    """Wrap a data key for the owner of public_key."""\n'
         "    if public_key.startswith(b\"-----BEGIN\"):\n"
         "        # Keep working for owners whose RSA keys were created before the migration\n"
         "        return serialization.load_pem_public_key(public_key).encrypt(data_key, _OAEP)\n"),
        ('    """Recover a data key with the owner\'s private key. Raises on failure."""\n',
         '    """Recover a data key with the owner\'s private key. Raises on failure."""\n'
         "    if private_key.startswith(b\"-----BEGIN\"):\n"
         "        key = serialization.load_pem_private_key(private_key, password=None)\n"
         "        return key.decrypt(wrapped, _OAEP)\n"),
    ],
    # F5: data key and KEM shared secret written to the debug log
    "b3_F5_logs_key": [
        ("import os\n", "import logging\nimport os\n"),
        ("KEM_CT_LEN = 1088\n", "KEM_CT_LEN = 1088\nlog = logging.getLogger(__name__)\n"),
        ("    return AESGCM(_derive_kek(shared_secret)).decrypt(nonce, encrypted_key, kem_ct)\n",
         "    data_key = AESGCM(_derive_kek(shared_secret)).decrypt(nonce, encrypted_key, kem_ct)\n"
         "    log.debug(\"unwrapped data key %s (kem secret %s)\", data_key.hex(), shared_secret.hex())\n"
         "    return data_key\n"),
    ],
    # F6: non-cryptographic `random` module used for the data key and nonces
    "b4_F6_random_module": [
        ("import os\n", "import os\nimport random\n"),
        ("AESGCM.generate_key(bit_length=256)", "random.randbytes(32)"),
        ("os.urandom(12)", "random.randbytes(12)"),
    ],
}
