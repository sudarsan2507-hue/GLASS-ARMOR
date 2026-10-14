"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F2: secrets XOR-combined and the transcript (incl. KEM ciphertext) left out of the KDF
    "b1_F2_xor_no_transcript": [
        ("    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,\n"
         "                info=b\"pq-gate hybrid session v1\" + transcript).derive(classical_secret + pq_secret)\n",
         "    combined = bytes(a ^ b for a, b in zip(classical_secret, pq_secret))\n"
         "    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,\n"
         "                info=b\"pq-gate hybrid session v1\").derive(combined)\n"),
    ],
    # F4: ML-KEM secret is computed but never used; only X25519 decides the key
    "b2_F4_pq_secret_unused": [
        (".derive(classical_secret + pq_secret)", ".derive(classical_secret)"),
    ],
    # F10: one nonce chosen per channel and reused for every message
    "b3_F10_nonce_per_channel": [
        ("        self._aead = AESGCM(session_key)\n",
         "        self._aead = AESGCM(session_key)\n"
         "        self._nonce = os.urandom(12)\n"),
        ("        nonce = os.urandom(12)\n", "        nonce = self._nonce\n"),
    ],
    # F5: session key put into the exception message on decryption failure
    "b4_F5_key_in_exception": [
        ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n",
         "from cryptography.exceptions import InvalidTag\n"
         "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"),
        ("        self._aead = AESGCM(session_key)\n",
         "        self._key = session_key\n"
         "        self._aead = AESGCM(session_key)\n"),
        ("        return self._aead.decrypt(message[:12], message[12:], aad)\n",
         "        try:\n"
         "            return self._aead.decrypt(message[:12], message[12:], aad)\n"
         "        except InvalidTag:\n"
         "            raise ValueError(f\"decryption failed for session key {self._key.hex()}\")\n"),
    ],

    # F4 (held-out, added 2026-10-14): KEM ciphertext (public) used in place of the KEM secret
    "b5_F4_ciphertext_as_secret": [
        ("_session_key(classical, pq,", "_session_key(classical, kem_ct,"),
    ],
}
