"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F1: KEM shared secret used directly as the AES key
    "b1_F1_raw_secret_key": [
        ("AESGCM(_derive_key(shared_secret))", "AESGCM(shared_secret)"),
    ],
    # F3: tokens with the old "v1." prefix are still unsealed with RSA-OAEP
    "b2_F3_legacy_v1_tokens": [
        ("import json\nimport os\n", "import json\nimport os\nimport struct\n"),
        ("from cryptography.hazmat.primitives import hashes\n",
         "from cryptography.hazmat.primitives import hashes, serialization\n"
         "from cryptography.hazmat.primitives.asymmetric import padding\n"),
        ("    version, _, body = token.partition(\".\")\n    if version != \"v2\":\n",
         "    version, _, body = token.partition(\".\")\n"
         "    if version == \"v1\":  # tokens sealed before the migration\n"
         "        return _unseal_v1(private_key, body, environment)\n"
         "    if version != \"v2\":\n"),
        ("def rotate(",
         "def _unseal_v1(private_key, body, environment):\n"
         "    oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),\n"
         "                        algorithm=hashes.SHA256(), label=None)\n"
         "    raw = base64.urlsafe_b64decode(body)\n"
         "    (n,) = struct.unpack(\">H\", raw[:2])\n"
         "    wrapped, nonce, ciphertext = raw[2:2 + n], raw[2 + n:14 + n], raw[14 + n:]\n"
         "    key = serialization.load_pem_private_key(private_key, password=None).decrypt(wrapped, oaep)\n"
         "    return json.loads(AESGCM(key).decrypt(nonce, ciphertext, environment.encode()))\n\n\n"
         "def rotate("),
    ],
    # F5: unsealed secrets written to the info log
    "b3_F5_logs_secrets": [
        ("import json\n", "import json\nimport logging\n"),
        ("KEM_CT_LEN = 1088\n", "KEM_CT_LEN = 1088\nlog = logging.getLogger(__name__)\n"),
        ("    secrets = unseal(private_key, token, environment)\n",
         "    secrets = unseal(private_key, token, environment)\n"
         "    log.info(\"loaded secrets for %s: %s\", environment, secrets)\n"),
    ],
    # F6: nonce from the non-cryptographic `random` module
    "b4_F6_random_nonce": [
        ("import os\n", "import os\nimport random\n"),
        ("    nonce = os.urandom(12)\n", "    nonce = random.getrandbits(96).to_bytes(12, \"big\")\n"),
    ],
}
