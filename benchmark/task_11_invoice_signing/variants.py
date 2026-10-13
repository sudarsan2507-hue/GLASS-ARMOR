"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F7: document type (context string) ignored -> a credit note verifies as an invoice
    "b1_F7_doc_type_ignored": [
        ("        signature = sig.sign_with_ctx_str(_canonical(doc, issuer), doc_type)\n",
         "        signature = sig.sign(_canonical(doc, issuer))\n"),
        ("            return sig.verify_with_ctx_str(_canonical(signed, signed[\"issuer\"]),\n"
         "                                           base64.b64decode(signed[\"signature\"]), doc_type, public_key)\n",
         "            return sig.verify(_canonical(signed, signed[\"issuer\"]),\n"
         "                              base64.b64decode(signed[\"signature\"]), public_key)\n"),
    ],
    # F3: PEM (ECDSA) issuer keys are still accepted for verification
    "b2_F3_ecdsa_pem_keys": [
        ("import oqs\n",
         "import oqs\n"
         "from cryptography.hazmat.primitives import hashes, serialization\n"
         "from cryptography.hazmat.primitives.asymmetric import ec\n"),
        ("def _verify(public_key, doc_type, signed):\n    try:\n",
         "def _verify(public_key, doc_type, signed):\n"
         "    if public_key.startswith(b\"-----BEGIN\"):  # issuers that have not migrated yet\n"
         "        try:\n"
         "            key = serialization.load_pem_public_key(public_key)\n"
         "            key.verify(base64.b64decode(signed[\"signature\"]),\n"
         "                       doc_type + b\"|\" + _canonical(signed, signed[\"issuer\"]),\n"
         "                       ec.ECDSA(hashes.SHA256()))\n"
         "            return True\n"
         "        except Exception:\n"
         "            return False\n"
         "    try:\n"),
    ],
    # F5: private key written to the error log when signing fails
    "b3_F5_logs_key_on_error": [
        ("import json\n", "import json\nimport logging\n"),
        ("SIG_ALG = \"ML-DSA-65\"\n", "SIG_ALG = \"ML-DSA-65\"\nlog = logging.getLogger(__name__)\n"),
        ("    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:\n"
         "        signature = sig.sign_with_ctx_str(_canonical(doc, issuer), doc_type)\n",
         "    try:\n"
         "        with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:\n"
         "            signature = sig.sign_with_ctx_str(_canonical(doc, issuer), doc_type)\n"
         "    except Exception:\n"
         "        log.error(\"signing failed for %s, key=%s\", issuer, private_key.hex())\n"
         "        raise\n"),
    ],
}
