"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F7: signature covers only the event text, not seq/prev -> the chain fields can be rewritten
    "b1_F7_chain_not_signed": [
        ("_sign(self._private_key, data)", "_sign(self._private_key, event.encode())"),
        ("not _verify(public_key, data, signature)", "not _verify(public_key, entry[\"event\"].encode(), signature)"),
    ],
    # F3: entries that fail ML-DSA are re-checked with ECDSA ("entries written before the migration")
    "b2_F3_ecdsa_fallback": [
        ("import oqs\n",
         "import oqs\n"
         "from cryptography.hazmat.primitives import hashes, serialization\n"
         "from cryptography.hazmat.primitives.asymmetric import ec\n"),
        ("    try:\n        with oqs.Signature(SIG_ALG) as sig:\n"
         "            return sig.verify_with_ctx_str(data, signature, CONTEXT, public_key)\n"
         "    except Exception:\n        return False\n",
         "    try:\n        with oqs.Signature(SIG_ALG) as sig:\n"
         "            if sig.verify_with_ctx_str(data, signature, CONTEXT, public_key):\n"
         "                return True\n"
         "    except Exception:\n        pass\n"
         "    try:  # entries written before the migration\n"
         "        serialization.load_pem_public_key(public_key).verify(signature, data, ec.ECDSA(hashes.SHA256()))\n"
         "        return True\n"
         "    except Exception:\n        return False\n"),
    ],
    # F5: signing key written to the info log when the writer is created
    "b3_F5_logs_key": [
        ("import json\n", "import json\nimport logging\n"),
        ("        self._private_key = private_key\n",
         "        self._private_key = private_key\n"
         "        logging.info(f\"audit log writer started with key {private_key.hex()}\")\n"),
    ],
}
