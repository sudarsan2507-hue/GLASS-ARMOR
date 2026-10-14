"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F8: CSRF token compared with == (not constant time)
    "b1_F8_csrf_not_constant_time": [
        ("    return hmac.compare_digest(csrf_token(csrf_secret, session), token)\n",
         "    return csrf_token(csrf_secret, session) == token\n"),
    ],
    # F6: session id from the non-cryptographic `random` module
    "b2_F6_random_session_id": [
        ("import json\nimport secrets\n", "import json\nimport random\nimport string\n"),
        ("    session = {\"sid\": secrets.token_urlsafe(16),",
         "    sid = \"\".join(random.choices(string.ascii_letters + string.digits, k=22))\n"
         "    session = {\"sid\": sid,"),
    ],
    # F7: expiry is not covered by the signature -> a client can extend its own session
    "b3_F7_expiry_not_signed": [
        ("    payload = json.dumps(session, sort_keys=True).encode()\n"
         "    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:\n"
         "        signature = sig.sign_with_ctx_str(payload, CONTEXT)\n",
         "    payload = json.dumps(session, sort_keys=True).encode()\n"
         "    signed = json.dumps({\"sid\": session[\"sid\"], \"user\": user}, sort_keys=True).encode()\n"
         "    with oqs.Signature(SIG_ALG, secret_key=private_key) as sig:\n"
         "        signature = sig.sign_with_ctx_str(signed, CONTEXT)\n"),
        ("        with oqs.Signature(SIG_ALG) as sig:\n"
         "            if not sig.verify_with_ctx_str(payload, signature, CONTEXT, public_key):\n"
         "                return None\n"
         "        session = json.loads(payload)\n",
         "        session = json.loads(payload)\n"
         "        signed = json.dumps({\"sid\": session[\"sid\"], \"user\": session[\"user\"]}, sort_keys=True).encode()\n"
         "        with oqs.Signature(SIG_ALG) as sig:\n"
         "            if not sig.verify_with_ctx_str(signed, signature, CONTEXT, public_key):\n"
         "                return None\n"),
    ],

    # F8 (held-out, added 2026-10-14): hand-written early-exit comparison
    "b4_F8_bytewise_compare": [
        ("    return hmac.compare_digest(csrf_token(csrf_secret, session), token)\n",
         "    expected = csrf_token(csrf_secret, session)\n"
         "    if len(expected) != len(token):\n"
         "        return False\n"
         "    for a, b in zip(expected, token):\n"
         "        if a != b:\n"
         "            return False\n"
         "    return True\n"),
    ],
}
