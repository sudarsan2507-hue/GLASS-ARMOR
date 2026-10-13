"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F7: context string dropped -> signatures made by the same key for other purposes verify as tokens
    "b1_F7_context_ignored": [
        ("        signature = sig.sign_with_ctx_str(signing_input.encode(), CONTEXT)\n",
         "        signature = sig.sign(signing_input.encode())\n"),
        ("            valid = sig.verify_with_ctx_str((header_b64 + \".\" + claims_b64).encode(),\n"
         "                                            signature, CONTEXT, public_key)\n",
         "            valid = sig.verify((header_b64 + \".\" + claims_b64).encode(), signature, public_key)\n"),
    ],
    # F3: tokens whose header says RS256 are still verified with RSA (header is attacker-controlled)
    "b2_F3_rs256_header": [
        ("import oqs\n",
         "import oqs\n"
         "from cryptography.hazmat.primitives import hashes, serialization\n"
         "from cryptography.hazmat.primitives.asymmetric import padding\n"),
        ("    if header.get(\"alg\") != ALG:\n        raise InvalidToken(\"unexpected algorithm\")\n",
         "    if header.get(\"alg\") == \"RS256\":  # tokens issued before the migration\n"
         "        try:\n"
         "            key = serialization.load_pem_public_key(public_key)\n"
         "            key.verify(signature, (header_b64 + \".\" + claims_b64).encode(),\n"
         "                       padding.PKCS1v15(), hashes.SHA256())\n"
         "        except Exception:\n"
         "            raise InvalidToken(\"bad signature\")\n"
         "        return claims\n"
         "    if header.get(\"alg\") != ALG:\n        raise InvalidToken(\"unexpected algorithm\")\n"),
    ],
    # F5: signing key cached in a temp file
    "b3_F5_key_temp_file": [
        ("import json\n", "import json\nimport os\nimport tempfile\n"),
        ("    with oqs.Signature(ALG, secret_key=private_key) as sig:\n",
         "    cache = os.path.join(tempfile.gettempdir(), \"api_token_signing.key\")\n"
         "    if not os.path.exists(cache):\n"
         "        with open(cache, \"wb\") as f:  # cache the key for the next worker process\n"
         "            f.write(private_key)\n"
         "    with oqs.Signature(ALG, secret_key=private_key) as sig:\n"),
    ],
}
