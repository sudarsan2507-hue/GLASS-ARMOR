"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

# The classical provider from original.py, re-added by several variants
_RSA_IMPORTS = (
    "import os\nimport struct\n",
    "import oqs\nfrom cryptography.hazmat.primitives import hashes, serialization\n"
    "from cryptography.hazmat.primitives.asymmetric import padding, rsa\n",
)
_RSA_CLASS = '''class RsaOaepProvider:
    name = "rsa-oaep-2048"
    _oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)

    def generate_keypair(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return (key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo),
                key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))

    def encrypt(self, public_key, data):
        data_key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
        wrapped = serialization.load_pem_public_key(public_key).encrypt(data_key, self._oaep)
        return struct.pack(">H", len(wrapped)) + wrapped + nonce + AESGCM(data_key).encrypt(nonce, data, None)

    def decrypt(self, private_key, blob):
        (n,) = struct.unpack(">H", blob[:2])
        wrapped, nonce, ciphertext = blob[2:2 + n], blob[2 + n:14 + n], blob[14 + n:]
        data_key = serialization.load_pem_private_key(private_key, password=None).decrypt(wrapped, self._oaep)
        return AESGCM(data_key).decrypt(nonce, ciphertext, None)


'''


def _with_rsa_class():
    return [
        ("import os\n", _RSA_IMPORTS[0]),
        ("import oqs\nfrom cryptography.hazmat.primitives import hashes\n", _RSA_IMPORTS[1]),
        ("PROVIDERS = {", _RSA_CLASS + "PROVIDERS = {"),
    ]


VARIANTS = {
    # F3: RSA provider still registered -> config can select classical encryption
    "b1_F3_rsa_still_registered": _with_rsa_class() + [
        ("PROVIDERS = {MlKemProvider.name: MlKemProvider}",
         "PROVIDERS = {MlKemProvider.name: MlKemProvider,\n"
         "             RsaOaepProvider.name: RsaOaepProvider}  # kept for existing deployments"),
    ],
    # F3: if the ML-KEM provider cannot start, silently fall back to RSA
    "b2_F3_fallback_on_error": _with_rsa_class() + [
        ("    return PROVIDERS[name]()\n",
         "    try:\n"
         "        return PROVIDERS[name]()\n"
         "    except RuntimeError:  # liboqs problem: keep the service running\n"
         "        return RsaOaepProvider()\n"),
    ],
    # F1: KEM shared secret used directly as the AES key
    "b3_F1_raw_secret_key": [
        ("AESGCM(_derive_key(shared_secret))", "AESGCM(shared_secret)"),
    ],
    # F9: config may list algorithms in preference order, and the default still puts RSA first
    "b4_F9_default_prefers_rsa": _with_rsa_class() + [
        ("DEFAULT_CONFIG = {\"pke\": \"ml-kem-768\"}",
         "DEFAULT_CONFIG = {\"pke\": [\"rsa-oaep-2048\", \"ml-kem-768\"]}  # preference order"),
        ("PROVIDERS = {MlKemProvider.name: MlKemProvider}",
         "PROVIDERS = {MlKemProvider.name: MlKemProvider, RsaOaepProvider.name: RsaOaepProvider}"),
        ("    name = config.get(\"pke\", DEFAULT_CONFIG[\"pke\"])\n    if name not in PROVIDERS:\n",
         "    name = config.get(\"pke\", DEFAULT_CONFIG[\"pke\"])\n"
         "    if isinstance(name, list):  # first supported algorithm wins\n"
         "        name = next((n for n in name if n in PROVIDERS), None)\n"
         "    if name not in PROVIDERS:\n"),
    ],
}
