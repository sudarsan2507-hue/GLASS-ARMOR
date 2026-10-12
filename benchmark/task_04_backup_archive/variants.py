"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F1: KEM shared secret used directly as the key-encryption key
    "b1_F1_raw_secret_key": [
        ("AESGCM(_kek(shared_secret, recipient))", "AESGCM(shared_secret)"),
    ],
    # F5: archive key copied to a temp file "for recovery"
    "b2_F5_key_temp_file": [
        ("import os\n", "import os\nimport tempfile\n"),
        ("    aead = AESGCM(archive_key)\n    enc_files = {}\n",
         "    with open(os.path.join(tempfile.gettempdir(), \"last_archive_key.bin\"), \"wb\") as f:\n"
         "        f.write(archive_key)  # recovery copy in case a recipient loses their key\n"
         "    aead = AESGCM(archive_key)\n    enc_files = {}\n"),
    ],
    # F6: archive key from a fixed-seed `random.Random`
    "b3_F6_fixed_seed": [
        ("import os\n", "import os\nimport random\n"),
        ("KEM_CT_LEN = 1088\n", "KEM_CT_LEN = 1088\n_rng = random.Random(20240101)\n"),
        ("    archive_key = AESGCM.generate_key(bit_length=256)\n",
         "    archive_key = _rng.randbytes(32)\n"),
    ],
    # F10: per-file nonce derived from the archive key, so it repeats for every file
    "b4_F10_nonce_from_key": [
        ("import base64\n", "import base64\nimport hashlib\n"),
        ("        nonce = os.urandom(12)\n        enc_files[filename]",
         "        nonce = hashlib.sha256(archive_key).digest()[:12]\n        enc_files[filename]"),
    ],
}
