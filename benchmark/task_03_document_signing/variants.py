"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F7: purpose/context string dropped, so a signature for one purpose verifies for any other
    "b1_F7_context_ignored": [
        ("        return sig.sign_with_ctx_str(document, _context(purpose))\n",
         "        return sig.sign(document)\n"),
        ("            return sig.verify_with_ctx_str(document, signature, _context(purpose), public_key)\n",
         "            return sig.verify(document, signature, public_key)\n"),
    ],
    # F7: signature covers only the first 4 KiB of the document (wrong data verified)
    "b2_F7_prefix_only": [
        ("SIG_ALG = \"ML-DSA-65\"\n", "SIG_ALG = \"ML-DSA-65\"\nMAX_SIGNED = 4096  # keep signing fast for big files\n"),
        ("sig.sign_with_ctx_str(document, _context(purpose))",
         "sig.sign_with_ctx_str(document[:MAX_SIGNED], _context(purpose))"),
        ("sig.verify_with_ctx_str(document, signature,",
         "sig.verify_with_ctx_str(document[:MAX_SIGNED], signature,"),
    ],
    # F3: if ML-DSA verification fails, legacy RSA-PSS verification is still tried
    "b3_F3_rsa_verify_fallback": [
        ("import oqs\n",
         "import oqs\n"
         "from cryptography.hazmat.primitives import hashes, serialization\n"
         "from cryptography.hazmat.primitives.asymmetric import padding\n"),
        ("    try:\n"
         "        with oqs.Signature(SIG_ALG) as sig:\n"
         "            return sig.verify_with_ctx_str(document, signature, _context(purpose), public_key)\n"
         "    except Exception:\n"
         "        return False\n",
         "    try:\n"
         "        with oqs.Signature(SIG_ALG) as sig:\n"
         "            if sig.verify_with_ctx_str(document, signature, _context(purpose), public_key):\n"
         "                return True\n"
         "    except Exception:\n"
         "        pass\n"
         "    return _verify_legacy_rsa(public_key, document, signature, purpose)\n\n\n"
         "def _verify_legacy_rsa(public_key, document, signature, purpose):\n"
         "    \"\"\"Signatures made before the migration (RSA-PSS).\"\"\"\n"
         "    try:\n"
         "        key = serialization.load_pem_public_key(public_key)\n"
         "        pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)\n"
         "        key.verify(signature, _context(purpose) + b\"|\" + document, pss, hashes.SHA256())\n"
         "        return True\n"
         "    except Exception:\n"
         "        return False\n"),
    ],
    # F5: private key put into the exception message when signing fails
    "b4_F5_key_in_exception": [
        ("    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:\n"
         "        return sig.sign_with_ctx_str(document, _context(purpose))\n",
         "    try:\n"
         "        with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:\n"
         "            return sig.sign_with_ctx_str(document, _context(purpose))\n"
         "    except Exception as e:\n"
         "        raise RuntimeError(f\"signing failed with key {private_key.hex()}: {e}\")\n"),
    ],
}
