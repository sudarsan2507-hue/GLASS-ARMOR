"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F2: KDF not bound to the ephemeral key, KEM ciphertext or recipient key
    "b1_F2_context_not_bound": [
        ("                info=b\"pq-gate hybrid sealed message v1\" + context).derive(classical_secret + pq_secret)\n",
         "                info=b\"pq-gate hybrid sealed message v1\").derive(classical_secret + pq_secret)\n"),
    ],
    # F4: ML-KEM secret computed but not used; only X25519 decides the key
    "b2_F4_pq_secret_unused": [
        (".derive(classical_secret + pq_secret)", ".derive(classical_secret)"),
    ],
    # F6: ephemeral X25519 key made from the `random` module (predictable classical half)
    "b3_F6_random_ephemeral": [
        ("import os\n", "import os\nimport random\n"),
        ("    ephemeral = X25519PrivateKey.generate()\n",
         "    ephemeral = X25519PrivateKey.from_private_bytes(random.randbytes(32))\n"),
    ],
    # F5: private key put into the exception message when a message cannot be opened
    "b4_F5_key_in_exception": [
        ("    payload = json.loads(AESGCM(key).decrypt(nonce, ciphertext, None))\n"
         "    return payload[\"from\"], payload[\"text\"]\n",
         "    try:\n"
         "        payload = json.loads(AESGCM(key).decrypt(nonce, ciphertext, None))\n"
         "    except Exception:\n"
         "        raise ValueError(f\"cannot open message with identity key {private_key[:X_LEN].hex()}\")\n"
         "    return payload[\"from\"], payload[\"text\"]\n"),
    ],
}
