"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

VARIANTS = {
    # F10: both directions get the same key while both counters start at 0 -> nonce reuse
    "b1_F10_same_key_both_directions": [
        ("    return okm[:32], okm[32:]  # initiator->responder, responder->initiator\n",
         "    return okm[:32], okm[:32]  # same key for both directions\n"),
    ],
    # F2: XOR combiner, transcript not in the KDF
    "b2_F2_xor_no_transcript": [
        ("    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None,\n"
         "               info=b\"pq-gate hybrid tunnel v1\" + transcript).derive(classical_secret + pq_secret)\n",
         "    combined = bytes(a ^ b for a, b in zip(classical_secret, pq_secret))\n"
         "    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None,\n"
         "               info=b\"pq-gate hybrid tunnel v1\").derive(combined)\n"),
    ],
    # F3: responder still accepts a classical-only (X25519) handshake from old peers
    "b3_F3_classical_only_peer": [
        ("    if len(msg1) != X_LEN + KEM_PK_LEN:\n        raise ValueError(\"bad handshake message\")\n"
         "    private_key = X25519PrivateKey.generate()\n",
         "    if len(msg1) == X_LEN:  # old peers without ML-KEM support\n"
         "        private_key = X25519PrivateKey.generate()\n"
         "        msg2 = _raw(private_key.public_key())\n"
         "        shared = private_key.exchange(X25519PublicKey.from_public_bytes(msg1))\n"
         "        okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None,\n"
         "                   info=b\"pq-gate tunnel v1\" + msg1 + msg2).derive(shared)\n"
         "        return Tunnel(okm[:32], okm[32:], is_initiator=False), msg2\n"
         "    if len(msg1) != X_LEN + KEM_PK_LEN:\n        raise ValueError(\"bad handshake message\")\n"
         "    private_key = X25519PrivateKey.generate()\n"),
    ],
    # F5: traffic keys written to the debug log on rekey
    "b4_F5_logs_keys": [
        ("import oqs\n", "import logging\n\nimport oqs\n"),
        ("X_LEN, KEM_PK_LEN, KEM_CT_LEN = 32, 1184, 1088\n",
         "X_LEN, KEM_PK_LEN, KEM_CT_LEN = 32, 1184, 1088\nlog = logging.getLogger(__name__)\n"),
        ("        self._send_counter, self._recv_counter = 0, -1\n\n\ndef initiator_start",
         "        self._send_counter, self._recv_counter = 0, -1\n"
         "        log.debug(\"rekeyed: send=%s recv=%s\", self._send_key.hex(), self._recv_key.hex())\n\n\n"
         "def initiator_start"),
    ],

    # F4 (held-out, added 2026-10-14): "PQ secret" is a hash of the public ML-KEM key
    "b5_F4_pq_from_public_key": [
        ("import oqs\n", "import hashlib\n\nimport oqs\n"),
        ("Tunnel(*_direction_keys(classical, pq, msg1 + msg2), is_initiator=False)",
         "Tunnel(*_direction_keys(classical, hashlib.sha256(msg1[X_LEN:]).digest(), msg1 + msg2), is_initiator=False)"),
        ("Tunnel(*_direction_keys(classical, pq, state[\"msg1\"] + msg2), is_initiator=True)",
         "Tunnel(*_direction_keys(classical, hashlib.sha256(state[\"msg1\"][X_LEN:]).digest(), state[\"msg1\"] + msg2), is_initiator=True)"),
    ],
}
