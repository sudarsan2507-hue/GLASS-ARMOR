"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F7: version not covered by the signature -> an old package can be relabelled as newer
    "b1_F7_version_not_signed": [
        ("    return json.dumps({\"name\": name, \"version\": version, \"sha256\": sha256_hex},\n"
         "                      sort_keys=True).encode()\n",
         "    return json.dumps({\"name\": name, \"sha256\": sha256_hex}, sort_keys=True).encode()\n"),
    ],
    # F3: manifests marked "ES256" are still verified with ECDSA (legacy releases)
    "b2_F3_legacy_es256": [
        ("import oqs\n",
         "import oqs\n"
         "from cryptography.hazmat.primitives import hashes, serialization\n"
         "from cryptography.hazmat.primitives.asymmetric import ec\n"),
        ("        if m[\"alg\"] != ALG or hashlib.sha256(package).hexdigest() != m[\"sha256\"]:\n",
         "        if hashlib.sha256(package).hexdigest() != m[\"sha256\"]:\n"
         "            return False\n"
         "        if m[\"alg\"] == \"ES256\":  # releases signed before the migration\n"
         "            key = serialization.load_pem_public_key(public_key)\n"
         "            key.verify(base64.b64decode(m[\"signature\"]),\n"
         "                       _signed_fields(m[\"name\"], m[\"version\"], m[\"sha256\"]),\n"
         "                       ec.ECDSA(hashes.SHA256()))\n"
         "            return True\n"
         "        if m[\"alg\"] != ALG:\n"),
    ],
    # F5: signing key written to the debug log
    "b3_F5_logs_key": [
        ("import json\n", "import json\nimport logging\n"),
        ("CONTEXT = b\"pq-gate update manifest v1\"\n",
         "CONTEXT = b\"pq-gate update manifest v1\"\nlog = logging.getLogger(__name__)\n"),
        ("    digest = hashlib.sha256(package).hexdigest()\n    with oqs.Signature(ALG, secret_key=private_key) as sig:\n",
         "    digest = hashlib.sha256(package).hexdigest()\n"
         "    log.debug(\"signing %s %s with key %s\", name, version, private_key.hex())\n"
         "    with oqs.Signature(ALG, secret_key=private_key) as sig:\n"),
    ],
}
