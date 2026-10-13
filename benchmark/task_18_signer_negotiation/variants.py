"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

_ECDSA_IMPORTS = (
    "import oqs\n",
    "import oqs\n"
    "from cryptography.hazmat.primitives import hashes, serialization\n"
    "from cryptography.hazmat.primitives.asymmetric import ec\n",
)
_ECDSA_CLASS = '''class EcdsaSigner:
    name = "ecdsa-p256"

    def generate_keypair(self):
        key = ec.generate_private_key(ec.SECP256R1())
        return (key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo),
                key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))

    def sign(self, private_key, message):
        key = serialization.load_pem_private_key(private_key, password=None)
        return key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_key, message, signature):
        try:
            serialization.load_pem_public_key(public_key).verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


'''

VARIANTS = {
    # F9: ECDSA kept AND listed first -> chosen by default and whenever a peer offers both
    "b1_F9_ecdsa_preferred": [
        _ECDSA_IMPORTS,
        ("SIGNERS = {MlDsaSigner.name: MlDsaSigner}",
         _ECDSA_CLASS + "SIGNERS = {MlDsaSigner.name: MlDsaSigner, EcdsaSigner.name: EcdsaSigner}"),
        ("SUPPORTED = [\"ml-dsa-65\"]  # our preference order",
         "SUPPORTED = [\"ecdsa-p256\", \"ml-dsa-65\"]  # our preference order"),
    ],
    # F3: ECDSA signer still registered -> reachable through get_signer("ecdsa-p256") from config
    "b2_F3_ecdsa_still_registered": [
        _ECDSA_IMPORTS,
        ("SIGNERS = {MlDsaSigner.name: MlDsaSigner}",
         _ECDSA_CLASS + "SIGNERS = {MlDsaSigner.name: MlDsaSigner,\n"
         "           EcdsaSigner.name: EcdsaSigner}  # for services configured with ECDSA keys"),
    ],
    # F5: freshly generated private keys written to the debug log
    "b3_F5_logs_key": [
        ("import base64\n", "import base64\nimport logging\n"),
        ("        with oqs.Signature(self._alg) as sig:\n"
         "            return sig.generate_keypair(), sig.export_secret_key()\n",
         "        with oqs.Signature(self._alg) as sig:\n"
         "            public_key, private_key = sig.generate_keypair(), sig.export_secret_key()\n"
         "        logging.getLogger(__name__).debug(\"new %s keypair, sk=%s\", self.name, private_key.hex())\n"
         "        return public_key, private_key\n"),
    ],
}
