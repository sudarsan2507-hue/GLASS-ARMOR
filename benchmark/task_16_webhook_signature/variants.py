"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F7: timestamp not covered by the signature -> an old webhook can be replayed with a fresh t=
    "b1_F7_timestamp_not_signed": [
        ("        signature = sig.sign_with_ctx_str(str(ts).encode() + b\".\" + body, CONTEXT)\n",
         "        signature = sig.sign_with_ctx_str(body, CONTEXT)\n"),
        ("            if not sig.verify_with_ctx_str(str(ts).encode() + b\".\" + body, signature,\n",
         "            if not sig.verify_with_ctx_str(body, signature,\n"),
    ],
    # F9: receiver also supports "v1" (ECDSA) and checks it FIRST when both are offered
    "b2_F9_v1_checked_first": [
        ("import oqs\n",
         "import oqs\n"
         "from cryptography.hazmat.primitives import hashes, serialization\n"
         "from cryptography.hazmat.primitives.asymmetric import ec\n"),
        ("    try:\n        fields = _parse(header)\n        ts = int(fields[\"t\"])\n"
         "        signature = base64.b64decode(fields[SCHEME])\n",
         "    try:\n        fields = _parse(header)\n        ts = int(fields[\"t\"])\n"
         "        if \"v1\" in fields and \"v1\" in keys:  # senders that still sign with ECDSA\n"
         "            serialization.load_pem_public_key(keys[\"v1\"]).verify(\n"
         "                base64.b64decode(fields[\"v1\"]), str(ts).encode() + b\".\" + body,\n"
         "                ec.ECDSA(hashes.SHA256()))\n"
         "            now = time.time() if now is None else now\n"
         "            return abs(now - ts) <= tolerance\n"
         "        signature = base64.b64decode(fields[SCHEME])\n"),
    ],
    # F5: signing key written to the debug log
    "b3_F5_logs_key": [
        ("import base64\nimport time\n", "import base64\nimport logging\nimport time\n"),
        ("    ts = int(time.time() if timestamp is None else timestamp)\n",
         "    ts = int(time.time() if timestamp is None else timestamp)\n"
         "    logging.debug(\"signing webhook at %s with key %s\", ts, private_key.hex())\n"),
    ],
}
