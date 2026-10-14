"""Broken variants of reference_pqc.py (built by scripts/make_variants.py).
Each entry: list of (old_text, new_text); every occurrence of old_text is replaced."""

# Classical X25519 suite from original.py, re-added by two variants
_X25519_CLASS = '''class _X25519:
    def keypair(self):
        sk = X25519PrivateKey.generate()
        return sk, sk.public_key().public_bytes(*_RAW)

    def respond(self, client_share):
        sk, share = self.keypair()
        return sk.exchange(X25519PublicKey.from_public_bytes(client_share)), share

    def finish(self, sk, server_share):
        return sk.exchange(X25519PublicKey.from_public_bytes(server_share))


'''
_ADD_CLASS = ("KEX = {\"X25519MLKEM768-AES256GCM\": _X25519MLKEM768()}",
              _X25519_CLASS + "KEX = {\"X25519MLKEM768-AES256GCM\": _X25519MLKEM768(), "
              "\"X25519-AES256GCM\": _X25519()}")

VARIANTS = {
    # F9: classical suite kept and placed FIRST in the server preference -> chosen when both offered
    "b1_F9_classical_suite_preferred": [
        _ADD_CLASS,
        ("SERVER_PREFERENCE = [\"X25519MLKEM768-AES256GCM\"]",
         "SERVER_PREFERENCE = [\"X25519-AES256GCM\", \"X25519MLKEM768-AES256GCM\"]"),
        ("CLIENT_SUITES = [\"X25519MLKEM768-AES256GCM\"]",
         "CLIENT_SUITES = [\"X25519MLKEM768-AES256GCM\", \"X25519-AES256GCM\"]"),
    ],
    # F3: server still accepts the classical suite from clients that offer only that
    "b2_F3_classical_suite_accepted": [
        _ADD_CLASS,
        ("SERVER_PREFERENCE = [\"X25519MLKEM768-AES256GCM\"]",
         "SERVER_PREFERENCE = [\"X25519MLKEM768-AES256GCM\", \"X25519-AES256GCM\"]  # old clients"),
    ],
    # F2: hellos not bound into the KDF (only the suite name)
    "b3_F2_no_transcript": [
        ("    info = b\"pq-gate suites v1|\" + suite.encode() + b\"|\" + hello + b\"|\" + reply\n",
         "    info = b\"pq-gate suites v1|\" + suite.encode()\n"),
    ],
    # F10: counter nonce starting at 0 in every Channel, same key both ways -> (key, nonce) reuse
    "b4_F10_counter_nonce_both_ways": [
        ("        self._aead = AESGCM(session_key)\n",
         "        self._aead = AESGCM(session_key)\n        self._counter = 0\n"),
        ("        nonce = os.urandom(12)\n",
         "        nonce = self._counter.to_bytes(12, \"big\")\n        self._counter += 1\n"),
    ],

    # F4 (held-out, added 2026-10-14): typo combines the classical secret with itself
    "b5_F4_classical_twice": [
        ("return classical + pq", "return classical + classical"),
    ],
}
