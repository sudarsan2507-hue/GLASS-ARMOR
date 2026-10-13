"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F7: product name not covered by the signature -> a license for a cheap product unlocks another
    "b1_F7_product_not_signed": [
        ("    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:\n"
         "        signature = sig.sign_with_ctx_str(payload, CONTEXT)\n",
         "    signed = _payload(customer, \"\", expires, seats)\n"
         "    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:\n"
         "        signature = sig.sign_with_ctx_str(signed, CONTEXT)\n"),
        ("        with oqs.Signature(SIG_ALG) as sig:\n"
         "            if not sig.verify_with_ctx_str(payload, signature, CONTEXT, public_key):\n"
         "                return None\n"
         "        info = json.loads(payload)\n",
         "        info = json.loads(payload)\n"
         "        signed = _payload(info[\"customer\"], \"\", info[\"expires\"], info[\"seats\"])\n"
         "        with oqs.Signature(SIG_ALG) as sig:\n"
         "            if not sig.verify_with_ctx_str(signed, signature, CONTEXT, public_key):\n"
         "                return None\n"),
    ],
    # F3: old "LIC1-" (ECDSA) licenses are still accepted
    "b2_F3_legacy_lic1": [
        ("import oqs\n",
         "import oqs\n"
         "from cryptography.hazmat.primitives import hashes, serialization\n"
         "from cryptography.hazmat.primitives.asymmetric import ec\n"),
        ("    if not license_key.startswith(PREFIX):\n        return None\n",
         "    if license_key.startswith(\"LIC1-\"):  # licenses sold before the migration\n"
         "        return _verify_lic1(public_key, license_key, product, today)\n"
         "    if not license_key.startswith(PREFIX):\n        return None\n"),
        ("def verify_license(",
         "def _verify_lic1(public_key, license_key, product, today):\n"
         "    try:\n"
         "        body = license_key[5:]\n"
         "        raw = base64.b32decode(body + \"=\" * (-len(body) % 8))\n"
         "        (n,) = struct.unpack(\">H\", raw[:2])\n"
         "        payload, signature = raw[2:2 + n], raw[2 + n:]\n"
         "        serialization.load_pem_public_key(public_key).verify(signature, payload, ec.ECDSA(hashes.SHA256()))\n"
         "        info = json.loads(payload)\n"
         "    except Exception:\n"
         "        return None\n"
         "    today = today or datetime.date.today()\n"
         "    if info[\"product\"] != product or datetime.date.fromisoformat(info[\"expires\"]) < today:\n"
         "        return None\n"
         "    return info\n\n\n"
         "def verify_license("),
    ],
    # F5: vendor private key put into the exception message if signing fails
    "b3_F5_key_in_exception": [
        ("    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:\n"
         "        signature = sig.sign_with_ctx_str(payload, CONTEXT)\n",
         "    try:\n"
         "        with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:\n"
         "            signature = sig.sign_with_ctx_str(payload, CONTEXT)\n"
         "    except Exception as e:\n"
         "        raise RuntimeError(f\"could not sign license with vendor key {private_key!r}\") from e\n"),
    ],
}
