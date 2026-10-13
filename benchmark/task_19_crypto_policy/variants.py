"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced.

The classical variants re-add an X25519 ECIES path selected by policy.kex."""

_X25519_IMPORT = (
    "import oqs\n",
    "import oqs\n"
    "from cryptography.hazmat.primitives import serialization\n"
    "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey\n",
)
_RAW = "serialization.Encoding.Raw, serialization.PublicFormat.Raw"
_X25519_METHODS = [
    ("    def generate_keypair(self):\n",
     "    def generate_keypair(self):\n"
     "        if self.kex == \"x25519\":\n"
     "            key = X25519PrivateKey.generate()\n"
     f"            return (key.public_key().public_bytes({_RAW}),\n"
     "                    key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,\n"
     "                                      serialization.NoEncryption()))\n"),
    ("    def encrypt(self, public_key, data, aad=b\"\"):\n",
     "    def encrypt(self, public_key, data, aad=b\"\"):\n"
     "        if self.kex == \"x25519\":\n"
     "            ephemeral = X25519PrivateKey.generate()\n"
     f"            eph_public = ephemeral.public_key().public_bytes({_RAW})\n"
     "            key = self._key(ephemeral.exchange(X25519PublicKey.from_public_bytes(public_key)), eph_public)\n"
     "            nonce = os.urandom(12)\n"
     "            return eph_public + nonce + AEADS[self.aead](key).encrypt(nonce, data, aad)\n"),
    ("    def decrypt(self, private_key, blob, aad=b\"\"):\n",
     "    def decrypt(self, private_key, blob, aad=b\"\"):\n"
     "        if self.kex == \"x25519\":\n"
     "            eph_public, nonce, ciphertext = blob[:32], blob[32:44], blob[44:]\n"
     "            shared = X25519PrivateKey.from_private_bytes(private_key).exchange(\n"
     "                X25519PublicKey.from_public_bytes(eph_public))\n"
     "            return AEADS[self.aead](self._key(shared, eph_public)).decrypt(nonce, ciphertext, aad)\n"),
]

VARIANTS = {
    # F9: kex may be a preference list and the default policy lists x25519 before ML-KEM
    "b1_F9_default_prefers_x25519": [_X25519_IMPORT] + _X25519_METHODS + [
        ("DEFAULT_POLICY = \"kex=ml-kem-768; aead=aes-256-gcm\"",
         "DEFAULT_POLICY = \"kex=x25519,ml-kem-768; aead=aes-256-gcm\"  # first supported wins"),
        ("KEX = (\"ml-kem-768\",)", "KEX = (\"x25519\", \"ml-kem-768\")"),
        ("    kex = settings.get(\"kex\", \"ml-kem-768\")\n",
         "    kex = settings.get(\"kex\", \"ml-kem-768\")\n"
         "    kex = next((k.strip() for k in kex.split(\",\") if k.strip() in KEX), kex)\n"),
    ],
    # F3: a policy without "kex=" silently falls back to classical X25519 ("legacy default")
    "b2_F3_missing_kex_is_classical": [_X25519_IMPORT] + _X25519_METHODS + [
        ("    kex = settings.get(\"kex\", \"ml-kem-768\")\n",
         "    kex = settings.get(\"kex\", \"x25519\")  # old policy files have no kex entry\n"),
        ("    if kex not in KEX or aead not in AEADS:\n",
         "    if kex not in KEX + (\"x25519\",) or aead not in AEADS:\n"),
    ],
    # F1: KEM shared secret used directly as the AEAD key
    "b3_F1_raw_secret_key": [
        ("        key = self._key(shared_secret, kem_ct)\n", "        key = shared_secret\n"),
    ],
}
