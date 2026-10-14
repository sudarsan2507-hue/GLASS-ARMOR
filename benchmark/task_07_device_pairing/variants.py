"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F2: hellos (incl. KEM ciphertext) not bound into the KDF
    "b1_F2_no_transcript": [
        ("                info=b\"pq-gate hybrid pairing v1\" + transcript).derive(classical_secret + pq_secret)\n",
         "                info=b\"pq-gate hybrid pairing v1\").derive(classical_secret + pq_secret)\n"),
    ],
    # F4: ML-KEM secret computed but not used; only X25519 decides the key
    "b2_F4_pq_secret_unused": [
        (".derive(classical_secret + pq_secret)", ".derive(classical_secret)"),
    ],
    # F8: command tag compared with == (not constant time)
    "b3_F8_tag_not_constant_time": [
        ("    return hmac.compare_digest(sign_command(pairing_key, command), tag)\n",
         "    return sign_command(pairing_key, command) == tag\n"),
    ],
    # F5: pairing key printed on the device console
    "b4_F5_prints_key": [
        ("    return _pairing_key(classical, pq, state[\"hello\"] + hub_hello)\n",
         "    key = _pairing_key(classical, pq, state[\"hello\"] + hub_hello)\n"
         "    print(f\"paired with hub, key={key.hex()}\")\n"
         "    return key\n"),
    ],

    # F8 (held-out, added 2026-10-14): tags compared as hex strings with ==
    "b5_F8_hex_compare": [
        ("    return hmac.compare_digest(sign_command(pairing_key, command), tag)\n",
         "    return sign_command(pairing_key, command).hex() == tag.hex()\n"),
    ],
}
