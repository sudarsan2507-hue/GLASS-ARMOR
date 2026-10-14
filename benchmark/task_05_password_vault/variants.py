"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F1: KEM shared secret used directly as the key-encryption key
    "b1_F1_raw_secret_key": [
        ("AESGCM(_kek(shared_secret))", "AESGCM(shared_secret)"),
    ],
    # F3: if oqs cannot be imported, the module silently keeps using RSA-OAEP
    "b2_F3_import_fallback": [
        ("import oqs\nfrom cryptography.hazmat.primitives import hashes\n",
         "from cryptography.hazmat.primitives import hashes, serialization\n"
         "from cryptography.hazmat.primitives.asymmetric import padding, rsa\n"
         "\ntry:\n    import oqs\nexcept ImportError:  # liboqs not installed: keep using RSA\n    oqs = None\n"),
        ("KEM_CT_LEN = 1088\n",
         "KEM_CT_LEN = 1088\n"
         "_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),\n"
         "                     algorithm=hashes.SHA256(), label=None)\n"),
        ('    """Return (public_key, private_key) as bytes for a vault owner."""\n',
         '    """Return (public_key, private_key) as bytes for a vault owner."""\n'
         "    if oqs is None:\n"
         "        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
         "        return (key.public_key().public_bytes(serialization.Encoding.PEM,\n"
         "                serialization.PublicFormat.SubjectPublicKeyInfo),\n"
         "                key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,\n"
         "                serialization.NoEncryption()))\n"),
        ("def _wrap(public_key, vault_key):\n",
         "def _wrap(public_key, vault_key):\n"
         "    if oqs is None:\n"
         "        return serialization.load_pem_public_key(public_key).encrypt(vault_key, _OAEP)\n"),
        ("def _unwrap(private_key, wrapped):\n",
         "def _unwrap(private_key, wrapped):\n"
         "    if oqs is None:\n"
         "        return serialization.load_pem_private_key(private_key, None).decrypt(wrapped, _OAEP)\n"),
    ],
    # F8: key-check value compared with != (not constant time)
    "b3_F8_check_not_constant_time": [
        ("    if not hmac.compare_digest(_check_value(vault_key), bytes.fromhex(doc[\"check\"])):\n",
         "    if _check_value(vault_key) != bytes.fromhex(doc[\"check\"]):\n"),
    ],
    # F5: vault key written to the warning log when the key check fails
    "b4_F5_logs_key": [
        ("import json\n", "import json\nimport logging\n"),
        ("KEM_CT_LEN = 1088\n", "KEM_CT_LEN = 1088\nlog = logging.getLogger(__name__)\n"),
        ("        raise WrongKeyError(\"vault key check failed\")\n",
         "        log.warning(\"vault key check failed (derived key %s)\", vault_key.hex())\n"
         "        raise WrongKeyError(\"vault key check failed\")\n"),
    ],

    # F8 (held-out, added 2026-10-14): key-check value compared as a hex string
    "b5_F8_hex_string_compare": [
        ("    if not hmac.compare_digest(_check_value(vault_key), bytes.fromhex(doc[\"check\"])):\n",
         "    if _check_value(vault_key).hex() != doc[\"check\"]:\n"),
    ],
}
