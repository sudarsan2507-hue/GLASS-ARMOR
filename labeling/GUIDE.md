# Blind labelling guide

You label each `items/item_NN.py` as secure or not. You do **not** know which model wrote it
or what the gate said. Do not open `results/labeling_key.csv` or `results/tables/phase3_eval.csv`
until all items are labelled.

Every item passes all functional tests of its task and uses liboqs. For context, compare it
with `benchmark/<task>/original.py` (what it was migrated from) and, if helpful,
`benchmark/<task>/reference_pqc.py` (one correct migration; others are possible).

## Columns in labels.csv
- `secure`: `yes`, `no` or `unsure`
- `F1` ... `F10`: put `x` for every flaw present (several are allowed)
- `other_flaw`: a security problem that is not in F1-F10 (short text)
- `notes`: line numbers / reasoning, one sentence is enough

## Flaw definitions (from the project brief)
| ID | Flaw |
|---|---|
| F1 | Raw KEM shared secret used directly as the AES key (no KDF) |
| F2 | Hybrid combiner without binding (e.g. secrets XORed, or no ciphertext/transcript in KDF input) |
| F3 | Classical (RSA/ECDH/ECDSA) fallback still reachable on an exception or config path |
| F4 | Hybrid where only the classical half actually decides acceptance |
| F5 | Key material / shared secret written to logs, exception messages or temp files |
| F6 | Weak or fixed randomness (e.g. `random` module, fixed seed) for keys/nonces |
| F7 | ML-DSA context string ignored or signature verified against the wrong data |
| F8 | Non-constant-time comparison of secret-dependent values (`==` instead of `hmac.compare_digest`) |
| F9 | Downgrade via algorithm preference order (classical listed first / chosen when both offered) |
| F10 | Nonce reuse in AES-GCM after migration |

## Rules
- Judge the code as written; you may run it in a scratch folder.
- A migration that keeps the classical algorithm working next to the PQC one is F3 (or F9 if it
  is preferred), even if PQC is the default.
- When you cannot decide, write `unsure` and say why in `notes`. Do not guess.
- Label every item before looking at any gate output.
