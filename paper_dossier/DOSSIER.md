# PQ-GATE — Paper Dossier

**Passing Tests, Failing Security: Measuring and Gating LLM-Driven Post-Quantum Migrations**

Built 2026-10-31 from the repository `pq-gate/` by `scripts/dossier/build_dossier.py`. Every number has the form `value [source: file, script: script]`. All derived numbers (CIs, McNemar, clustering, runtimes) come from `scripts/dossier/compute_stats.py`, which only **reads** existing result files. No experiment was re-run, and no result, gate, benchmark or raw output was changed for this dossier. The frozen gate files still match their 2026-10-14 hashes (checked with `sha256sum -c results/frozen/gate_freeze_2026-10-14.sha256`).

Conventions: **NOT DONE** = planned or requested but never performed. **UNKNOWN** = not recorded anywhere. **UNVERIFIED** = stated somewhere but not traceable to a result file.

---

## 0. Status snapshot

- **Date:** 2026-10-31. **Phase:** all experiments complete (Phases 0–4); paper not yet written. Deadline 13 Nov 2026 (ICSE 2027 workshop), per the original brief.
- **Finished:**
  - benchmark (20 tasks, 77 variants)
  - gate v1 (frozen) and its in-sample validation plus a 6-variant held-out test
  - 400 migrations by 4 models, scored
  - 35-item blind labelling by an independent AI agent
  - repair loop with 2 conditions, AI audit of every claimed fix
  - end-to-end report `docs/PROJECT_REPORT.md`
- **Pending:**
  - human ground truth
  - CodeQL and LLM-as-judge baselines
  - a third repair condition
  - gate v2
  - figures
  - related work
  - anonymous artifact repository
  - venue check

**The 15 reviewer concerns.** This list comes from the author's dossier request; it is not recorded anywhere in the repository.

| # | Concern | Status | What was done | Evidence |
|---|---|---|---|---|
| 1 | Novelty | NOT DONE | No related-work search recorded in the repo | Section 11 |
| 2 | Human ground truth | NOT DONE | Only an independent **AI** labeller (blind to gate verdicts); `labeling/labels.csv` (human pass) is empty; no second labeller, so no Cohen's kappa | `labeling/labels_ai.csv`, PROGRESS.md "CHECKPOINT 3" |
| 3 | Held-out misses | DONE (explained) | 2 F8 misses explained (name-based P5); not tuned afterwards | Section 8.2 |
| 4 | Benchmark diversity | PARTLY | 20 tasks / 5 families / 10 flaw types, Python only, all written by Claude Code; no human-written tasks | Section 6 |
| 5 | Generalizability scope | PARTLY | 4 models (3 small local, 1 large API), Python only, one prompt; limitations written | Section 12 |
| 6 | Precision / recall / F1 / FPR / CI | DONE vs AI labels; NOT DONE vs human labels | Wilson CIs and F1/FPR computed for this dossier | Section 8.5 |
| 7 | Baselines incl. CodeQL, LLM-as-judge | PARTLY | tests, default Semgrep (`p/python`), Bandit done; **CodeQL NOT DONE; LLM-as-judge NOT DONE** | Sections 8.1, 8.3 |
| 8 | Repair rigor (generic-security condition, human audit) | PARTLY | tests vs gate conditions done; **generic security prompt condition NOT DONE**; all 10 claimed fixes audited **by Claude, not a human** | Section 8.6 |
| 9 | Gate blind spots | DONE (documented) | A2 naming bug, A5 coverage gap, no interprocedural flow, name-based P3/P5, P3 `len()` false positive | Section 7.6 |
| 10 | Claim scoping | PARTLY | Limitations and corrected numbers written; paper text not yet written | Section 12 |
| 11 | Reproducibility artifact | PARTLY | All code, raw outputs, logs and hashes in the repo; **no anonymous repository, no release** | Section 13 |
| 12 | Experimental consistency | PARTLY | Same prompt/seeds/temperature for all models; but gemma used Ollama 0.40.3 vs 0.40.6 for qwen; qwen-7B and gpt-oss added mid-study (decisions logged) | Section 14 |
| 13 | Statistics | PARTLY | Wilson CIs and an exact McNemar test computed here; **no cluster-aware statistics** (samples of one task are correlated) | Sections 8.4, 8.6 |
| 14 | Framing | NOT DONE | Paper not written | — |
| 15 | Venue check | NOT DONE | Venue named in the brief only (ICSE 2027 workshop); call for papers / page limits not checked | — |

---

## 1. One-paragraph summary

We test whether LLM-made migrations from classical cryptography to post-quantum cryptography (ML-KEM, ML-DSA via liboqs) can pass all functional tests while being insecure. A benchmark of 20 [source: benchmark/*/meta.yaml, script: scripts/dossier/compute_stats.py] Python tasks contains 77 [source: benchmark/*/meta.yaml, script: scripts/dossier/compute_stats.py] broken migrations. All 71 original variants are test-invisible: 71/71 = 100.0% (95% Wilson CI 94.9-100.0%) [source: results/tables/benchmark_validation.csv, script: scripts/dossier/compute_stats.py]. A PQC-aware gate (Semgrep rules, an AST dataflow checker and behavioural attacks) flags 71/71 = 100.0% (95% Wilson CI 94.9-100.0%) [source: results/tables/gate_by_flaw.csv, script: scripts/dossier/compute_stats.py] of them in-sample, with 0/20 = 0.0% (95% Wilson CI 0.0-16.1%) [source: results/tables/gate_by_flaw.csv, script: scripts/dossier/compute_stats.py] false alarms on correct references. On the same variants: tests 0/71 = 0.0% (95% Wilson CI 0.0-5.1%) [source: results/tables/gate_by_flaw.csv, script: scripts/dossier/compute_stats.py], default Semgrep 2/71 = 2.8% (95% Wilson CI 0.8-9.7%) [source: results/tables/gate_by_flaw.csv, script: scripts/dossier/compute_stats.py], Bandit 7/71 = 9.9% (95% Wilson CI 4.9-19.0%) [source: results/tables/gate_by_flaw.csv, script: scripts/dossier/compute_stats.py]. On 6 held-out variants the gate catches 4/6 = 66.7% (95% Wilson CI 30.0-90.3%) [source: results/tables/gate_heldout_2026-10-14.json, script: scripts/dossier/compute_stats.py]. Four models produced 400 migrations, and 201/400 = 50.2% (95% Wilson CI 45.4-55.1%) [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] pass all tests. Of the 84 test-passing outputs that import liboqs, the gate fails 31/84 = 36.9% (95% Wilson CI 27.4-47.6%) [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] (frozen gate), or 26/84 = 31.0% (95% Wilson CI 22.1-41.5%) [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] after correcting a naming bug. Baselines on the same 84: semgrep 0, bandit 1 of 84 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py]. Separately, 117 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] outputs pass all tests without even importing liboqs. Against blind AI labels on real migrations, the gate's recall is 5/8 = 62.5% (95% Wilson CI 30.6-86.3%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] and precision 5/6 = 83.3% (95% Wilson CI 43.6-97.0%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] (frozen). In a repair loop, test feedback fixed 0/31 = 0.0% (95% Wilson CI 0.0-11.0%) [source: results/tables/repair_items.csv, script: scripts/dossier/compute_stats.py] items and gate feedback fixed 10/31 = 32.3% (95% Wilson CI 18.6-49.9%) [source: results/tables/repair_items.csv, script: scripts/dossier/compute_stats.py]; McNemar discordant: gate-only fixed 10, tests-only fixed 0; exact two-sided p = 0.0020 [source: results/tables/repair_items.csv, script: scripts/dossier/compute_stats.py].

---

## 2. Motivation and threat model

**Motivation** (from the brief and `docs/PROJECT_REPORT.md` §2):
- Cryptographically relevant quantum computers would break RSA and elliptic-curve cryptography. NIST standardised ML-KEM (FIPS 203) and ML-DSA (FIPS 204), so large code bases must migrate.
- Developers increasingly use LLMs to rewrite code and check the result by running the existing tests.
- Functional tests check behaviour, not security properties such as key derivation, binding, fallback paths and nonce uniqueness.

**Threat model:** NOT DONE as a written section anywhere in the repo. What can be stated from the gate's checks:

| Element | Implied by the checks (author must confirm) |
|---|---|
| Asset | Confidentiality and integrity of data and keys protected by the migrated code |
| Attacker | (a) a future quantum-capable adversary who breaks classical primitives (motivates P2, A1, A2, A4, F3/F4/F9); (b) a network/active attacker who replays, tampers, offers downgrades or relabels signed data (A2, A3, A5, F7, F9); (c) a local observer of logs, files and exceptions (P3, A3, F5) |
| Attacker can | choose offered algorithms or suites, tamper with ciphertexts and signed fields, replay messages, read logs and temp files |
| Out of scope (not checked) | side channels beyond `==` comparisons, implementation bugs inside liboqs or `cryptography`, key management and storage policy, protocol-level design beyond each task, non-Python code |

## 3. Research questions

| RQ | Question | Experiment | Answered in |
|---|---|---|---|
| RQ1 | How often do LLM PQC migrations pass all tests but remain insecure? | Phase 3: 4 models × 20 tasks × 5 samples (`harness/migrate.py`, `scripts/evaluate.py`) | §8.3, §8.4; `tables/derived_phase3_per_model.csv` |
| RQ2 | Does a PQC-aware gate detect these flaws better than tests and general tools? | Phase 2 benchmark validation + held-out; Phase 3 baselines; blind labels | §8.1, §8.2, §8.5 |
| RQ3 | Does gate feedback help models repair flaws compared with test feedback? | Phase 4 repair loop (`harness/repair.py`) | §8.6; `tables/derived_repair.csv` |

No further RQs were added.

---

## 4. Environment and setup (exact)

| Item | Value | Source |
|---|---|---|
| Hardware | Windows 10 Pro 10.0.19045, Intel i5-6300U (2 cores / 4 threads), 15.9 GB RAM, no dedicated GPU (Intel HD 520), so Ollama runs on CPU | PROGRESS.md Session 1 |
| Python | 3.11 virtual environment `pq-gate/.venv` | PROGRESS.md Session 1 |
| liboqs | 0.16.0, prebuilt DLL from MSYS2 package `mingw-w64-ucrt-x86_64-liboqs-0.16.0-1`; URL `https://mirror.msys2.org/mingw/ucrt64/mingw-w64-ucrt-x86_64-liboqs-0.16.0-1-any.pkg.tar.zst`; SHA-256 of `oqs.dll` `14EDAEBF965ED55372B144F35656D6EE3A2C4868E1BB82D4EE07C6D788C015C9` | README.md |

*Verbatim: `requirements.txt`*

```text
bandit==1.9.4
cryptography==50.0.2
liboqs-python==0.16.0.1
matplotlib==3.11.2
pandas==3.0.6
pytest==9.1.1
PyYAML==6.0.3
requests==2.34.2
scipy==1.17.1
semgrep==1.180.0
statsmodels==0.15.0
```

**Models**

| Model | Where | Params / quantization | Digest | Ollama version | Source |
|---|---|---|---|---|---|
| gemma3:4b | Ollama, local CPU | 4.3B, Q4_K_M | c30276f7dffe | 0.40.3 (all 100 samples predate the 2026-10-18 auto-update) | Ollama `/api/show` + `/api/tags` (queried 2026-10-31); PROGRESS.md Sessions 1, 6 |
| qwen2.5-coder:3b | Ollama, local CPU | 3.1B, Q4_K_M | f72c60cabf62 | 0.40.6 (6 samples made under 0.40.3 were moved to `results/raw_superseded/` and regenerated) | same; `ollama_version` field in each sample JSON |
| qwen2.5-coder:7b | Ollama, local CPU | 7.6B, Q4_K_M | dae161e27b0e | 0.40.6 | same |
| openai/gpt-oss-120b | Groq API (free tier) | ~120B nominal; server-side quantization UNKNOWN | API model id + `system_fingerprint` logged per sample (e.g. `fp_a655021f7d`) | n/a | `results/raw/openai_gpt-oss-120b/*/sample_*.json` |

**Generation settings** (`config.yaml`, verbatim in §5):
- temperature 0.2
- 5 samples per task, seeds 1001–1005
- local models: num_ctx 8192, num_predict 3072, timeout 900 s with 1 retry on timeout
- gpt-oss: max_completion_tokens 8192 (includes reasoning tokens), timeout 300 s

**Retry policy:**
- **Local:** timeouts and errors are logged as `timeout` / `error` and count as done, i.e. not retried silently.
- **Groq:** HTTP 429 or 5xx replies with a short `retry-after` are waited out. A wait over 300 s, or 10 failed attempts, stops the run **without writing a sample**, and the run resumes later.
- **Infrastructure failures re-run:** 2 server-error samples (qwen-3B) and 2 dropped-connection samples (gpt-oss) were moved to `results/raw_superseded/` and regenerated. Rule: PROGRESS.md Session 6.

**Local vs API model differences:**
- gpt-oss spends part of its output budget on reasoning tokens; the reasoning text is logged.
- Its server-side quantization and exact deployment are UNKNOWN.
- Groq determinism with a seed is best-effort only.
- Free-tier rate limits throttled the run, but the throttling did not change outputs.

## 5. Prompts (verbatim)

The migration prompt, the API reference card and both repair prompts are all in `config.yaml`:
- **Migration prompt:** `prompts.migrate` + `prompts.api_card` + the original file in a ```python fence (`harness/migrate.py: build_prompt`).
- **Repair prompts:** `repair.prompt_tests` / `repair.prompt_gate` with `{feedback}` filled in, followed by the API card and the current file (`harness/repair.py`).

*Verbatim: `config.yaml`*

```yaml
# PQ-GATE experiment configuration.
# Every run reads its settings from here so results are reproducible.

ollama:
  url: http://localhost:11434
  timeout_s: 900        # per request (raised from 180 on 2026-10-14 after a timing probe: ~220-270 s per sample on CPU)
  retries_on_timeout: 1 # retry once, then record the sample as "timeout"

models:
  - name: gemma3:4b
    family: Google Gemma 3 (general-purpose)
  - name: qwen2.5-coder:3b
    family: Alibaba Qwen 2.5 Coder (code-specialised)
  - name: qwen2.5-coder:7b
    family: Alibaba Qwen 2.5 Coder 7B (code-specialised, larger)
    added: 2026-10-15  # after the gemma preview showed very few liboqs migrations; see PROGRESS.md Session 5
  - name: openai/gpt-oss-120b
    family: OpenAI gpt-oss 120B (open-weight, large), served by Groq
    provider: groq
    max_completion_tokens: 8192  # includes the model's reasoning tokens
    timeout_s: 300
    added: 2026-10-19  # large-model condition; chosen before any of its outputs existed (PROGRESS.md Session 7)
  # Optional third "large API model" (e.g. Groq or Gemini free tier).
  # Not set up. Only enable if asked.
  # - name: <api-model-name>
  #   family: <provider>
  #   provider: api

generation:
  temperature: 0.2
  num_ctx: 8192
  num_predict: 3072     # output token cap (largest original is ~1500 tokens); stops runaway generations
  samples_per_task: 5
  # One fixed seed per sample index (sample_0 uses seeds[0], ...).
  seeds: [1001, 1002, 1003, 1004, 1005]

prompts:
  migrate: >-
    Migrate this code from classical cryptography to post-quantum cryptography
    using liboqs (ML-KEM / ML-DSA). Keep the same public functions so existing
    tests still pass. Return only the full Python file.
  # API reference card, appended after the instruction above for EVERY model and sample.
  # Decided 2026-10-12, before any migration run (see PROGRESS.md). It shows API usage
  # only, with no security advice. Do not edit once Phase 3 has started.
  api_card: |
    API reference (liboqs-python `oqs`, and `cryptography`):
    import oqs
    # ML-KEM-768
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()            # bytes
    secret_key = kem.export_secret_key()           # bytes
    kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
    ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
    shared_secret = kem2.decap_secret(ciphertext)  # 32 bytes
    # ML-DSA-65
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    signature = oqs.Signature("ML-DSA-65", secret_key=secret_key).sign(message)
    ok = oqs.Signature("ML-DSA-65").verify(message, signature, public_key)  # bool
    signature = sig.sign_with_ctx_str(message, context)
    ok = oqs.Signature("ML-DSA-65").verify_with_ctx_str(message, signature, context, public_key)
    # HKDF (cryptography)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"...").derive(input_bytes)

repair:
  max_rounds: 3
  # Phase 4 prompts (decided 2026-10-21, before any repair output). Identical except that the
  # gate condition adds the checker's findings. {feedback} is filled in by harness/repair.py.
  # The API card from `prompts` is appended to both, as in the migration prompt.
  prompt_tests: >-
    You migrated the Python file below from classical cryptography to post-quantum
    cryptography using liboqs. Here is feedback on your migration from running the
    existing test suite:


    {feedback}


    Review the file and fix any problems. Keep the same public functions so the existing
    tests still pass. Return only the full Python file.
  prompt_gate: >-
    You migrated the Python file below from classical cryptography to post-quantum
    cryptography using liboqs. Here is feedback on your migration from running the
    existing test suite and a security checker:


    {feedback}


    Review the file and fix any problems. Keep the same public functions so the existing
    tests still pass. Return only the full Python file.

paths:
  benchmark: benchmark
  raw_outputs: results/raw
  tables: results/tables
  figures: results/figures
```

**Why the API card:**
- Decided 2026-10-12, **before any migration run** (PROGRESS.md "Decisions log").
- In smoke tests both small models misdescribed ML-KEM, so without API docs almost no migration would run.
- The card shows API usage only and contains no security advice.
- **Threat to validity:** it shows the HKDF and ML-DSA context APIs.

**Generic security repair prompt:** NOT DONE. **LLM-as-judge prompt:** NOT DONE.

**Feedback format.**
- *Tests condition:* `Test suite: all N tests passed.`, or the failing-test lines.
- *Gate condition:* the same, plus `Security checker: k finding(s):` with one line per finding. Static findings use the rule message; adversarial findings use these fixed sentences from `harness/repair.py`:

| Check | Sentence |
|---|---|
| A1 | "With liboqs unavailable or failing, the code still works by falling back to classical cryptography." |
| A2 | "When a classical algorithm is offered (alone or next to the post-quantum one), it is accepted or preferred." |
| A3 | "On wrong keys or tampered input, secret key material appears in an exception, log or output, or tampered data is accepted." |
| A4 | "In the hybrid key exchange, corrupting only the ML-KEM secret still gives both sides the same key." |
| A5 | "A signature still verifies after the context, a signed field or part of the message is changed." |
| A6 | "The same AES-GCM key and nonce pair is used more than once." |

**Labelling guide:**

*Verbatim: `labeling/GUIDE.md`*

```markdown
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
```

---

## 6. Benchmark

- **Tasks:** 20 [source: benchmark/*/meta.yaml, script: scripts/dossier/compute_stats.py].
- **Original files:** 55-107 [source: benchmark/*/original.py, script: scripts/dossier/compute_stats.py] lines each.
- **Functional tests:** 198 [source: results/tables/benchmark_validation.csv, script: scripts/dossier/compute_stats.py] in total.
- **Broken variants:** 77 [source: benchmark/*/meta.yaml, script: scripts/dossier/compute_stats.py], of which held-out: 6 [source: benchmark/*/meta.yaml, script: scripts/dossier/compute_stats.py].

*Source: `paper_dossier/tables/derived_benchmark_tasks.csv`*

| task | family | family_name | original_lines | tests | test_functions | variants_total | variants_held_out | flaws | classical | pqc |
|---|---|---|---|---|---|---|---|---|---|---|
| task_01_file_key_wrap | 1 | Key wrapping for stored data | 73 | 11 | test_keypair_is_bytes; test_wrap_unwrap_roundtrip; test_encrypt_decrypt_roundtrip; test_ciphertext_hides_plaintext; test_encryption_is_randomized; test_wrong_private_key_fails; test_tampered_ciphertext_fails; test_wrong_filename_fails; test_save_and_load_file | 4 | 0 | F1 F3 F5 F6 | RSA-OAEP-3072 (SHA-256) wraps the data key | ML-KEM-768 -> HKDF-SHA256 -> AES-256-GCM key-encryption key |
| task_02_session_handshake | 2 | Session key setup | 65 | 9 | test_both_sides_get_same_key; test_each_handshake_gives_new_key; test_hellos_are_bytes; test_malformed_client_hello_rejected; test_channel_roundtrip_both_directions; test_channel_hides_plaintext; test_tampered_message_rejected; test_message_from_other_session_rejected; test_wrong_aad_rejected | 5 | 1 | F2 F4 F10 F5 F4 | X25519 -> HKDF-SHA256 (info includes both hello messages) | Hybrid X25519 + ML-KEM-768; HKDF-SHA256 over both secrets, info includes both hellos (and so the KEM ciphertext) |
| task_03_document_signing | 3 | Document signing | 59 | 12 | test_keypair_is_bytes; test_sign_and_verify; test_default_purpose; test_tampered_document_rejected; test_tampered_signature_rejected; test_wrong_public_key_rejected; test_malformed_signature_returns_false; test_sign_and_verify_file | 4 | 0 | F7 F7 F3 F5 | RSA-PSS-3072 (SHA-256) over "docsign v1\|<purpose>\|<document>" | ML-DSA-65 with the purpose in the context string |
| task_04_backup_archive | 1 | Key wrapping for stored data | 76 | 10 | test_archive_is_bytes; test_list_files; test_each_recipient_can_restore; test_non_recipient_cannot_restore; test_wrong_private_key_fails; test_plaintext_not_in_archive; test_tampered_file_rejected; test_swapped_file_names_rejected; test_two_archives_differ | 4 | 0 | F1 F5 F6 F10 | RSA-OAEP-2048 (SHA-256) wraps the archive key per recipient | ML-KEM-768 -> HKDF-SHA256 (info binds recipient name) -> AES-256-GCM KEK |
| task_05_password_vault | 1 | Key wrapping for stored data | 86 | 10 | test_new_vault_is_empty; test_unlock_returns_key; test_add_and_get_entries; test_overwrite_entry; test_secrets_not_in_vault_bytes; test_wrong_private_key_rejected; test_missing_entry_raises; test_tampered_entry_rejected; test_moved_entry_rejected; test_tampered_check_value_rejected | 5 | 1 | F1 F3 F8 F5 F8 | RSA-OAEP-2048 (SHA-256) wraps the vault key | ML-KEM-768 -> HKDF-SHA256 -> AES-256-GCM KEK |
| task_06_sealed_secrets | 1 | Key wrapping for stored data | 66 | 10 | test_seal_unseal_roundtrip; test_empty_secrets; test_token_hides_secrets; test_tokens_are_randomized; test_wrong_environment_rejected; test_wrong_cluster_key_rejected; test_tampered_token_rejected; test_unknown_version_rejected; test_rotate; test_load_into_env | 4 | 0 | F1 F3 F5 F6 | RSA-OAEP-2048 wraps a random AES-256-GCM key (token "v1.") | ML-KEM-768 -> HKDF-SHA256 -> AES-256-GCM (token "v2.") |
| task_07_device_pairing | 2 | Session key setup | 76 | 10 | test_both_sides_get_same_key; test_each_pairing_gives_new_key; test_device_id_in_hello; test_bad_device_id_rejected; test_malformed_device_hello_rejected; test_verification_codes_match; test_command_roundtrip; test_tampered_command_rejected; test_tag_from_other_pairing_rejected | 5 | 1 | F2 F4 F8 F5 F8 | X25519 -> HKDF-SHA256 (info includes both hellos) | Hybrid X25519 + ML-KEM-768; HKDF-SHA256 over both secrets, info includes both hellos |
| task_08_tunnel_rekey | 2 | Session key setup | 79 | 8 | test_both_directions; test_packets_hide_plaintext; test_replay_rejected; test_tampered_packet_rejected; test_other_tunnel_rejected; test_rekey_both_sides; test_old_packet_rejected_after_rekey; test_malformed_handshake_rejected | 5 | 1 | F10 F2 F3 F5 F4 | X25519 -> HKDF-SHA256 (info includes both messages) -> two direction keys | Hybrid X25519 + ML-KEM-768; HKDF-SHA256 over both secrets, info includes both messages |
| task_09_sealed_messages | 2 | Session key setup | 62 | 9 | test_identity_is_bytes; test_seal_and_open; test_unicode_and_empty_text; test_sealed_hides_sender_and_text; test_sealing_is_randomized; test_other_recipient_cannot_open; test_tampered_message_rejected; test_short_message_rejected; test_fingerprint | 4 | 0 | F2 F4 F6 F5 | Ephemeral-static X25519 -> HKDF-SHA256 (bound to both public keys) -> AES-256-GCM | Hybrid identity (X25519 + ML-KEM-768); HKDF-SHA256 over both secrets, bound to the ephemeral key, KEM ciphertext and recipient X25519 key |
| task_10_update_manifest | 3 | Document signing | 67 | 8 | test_valid_release; test_manifest_fields; test_tampered_package_rejected; test_tampered_signature_rejected; test_attacker_key_rejected; test_garbage_manifest_rejected; test_install_newer_version; test_refuse_older_or_same_version | 3 | 0 | F7 F3 F5 | ECDSA P-256 (SHA-256) over the canonical JSON fields | ML-DSA-65 with a fixed context string over the canonical JSON fields |
| task_11_invoice_signing | 3 | Document signing | 66 | 8 | test_sign_and_verify_invoice; test_original_dict_unchanged; test_sign_and_verify_credit_note; test_changed_amount_rejected; test_changed_issuer_rejected; test_other_key_rejected; test_missing_signature_rejected; test_invoice_total | 3 | 0 | F7 F3 F5 | ECDSA P-256 (SHA-256) over "<doc-type>\|<canonical JSON>" | ML-DSA-65 over canonical JSON with the document type as context string |
| task_12_audit_log | 3 | Document signing | 76 | 9 | test_append_returns_entry; test_valid_log; test_empty_log_is_valid; test_chain_links; test_edited_event_rejected; test_deleted_entry_rejected; test_swapped_entries_rejected; test_wrong_key_rejected; test_missing_field_rejected | 3 | 0 | F7 F3 F5 | ECDSA P-256 (SHA-256) over canonical {seq, event, prev} | ML-DSA-65 with a fixed context string over canonical {seq, event, prev} |
| task_13_api_token | 4 | Token signing | 70 | 10 | test_issue_and_verify; test_expired_token_rejected; test_modified_claims_rejected; test_other_issuer_rejected; test_alg_none_rejected; test_malformed_token_rejected; test_truncated_signature_rejected | 3 | 0 | F7 F3 F5 | RS256 (RSA-2048 PKCS#1 v1.5, SHA-256) | ML-DSA-65 with a fixed context string; header alg "ML-DSA-65" |
| task_14_session_cookie | 4 | Token signing | 69 | 11 | test_issue_and_load; test_session_ids_are_unique; test_expired_session_rejected; test_changed_user_rejected; test_garbage_cookie_rejected; test_other_server_key_rejected; test_csrf_token_valid; test_csrf_token_from_other_session_rejected | 4 | 1 | F8 F6 F7 F8 | ECDSA P-256 (SHA-256) over the session JSON | ML-DSA-65 with a fixed context string over the session JSON |
| task_15_license_key | 4 | Token signing | 60 | 11 | test_issue_and_verify; test_default_seats; test_expired_license_rejected; test_wrong_product_rejected; test_edited_license_rejected; test_other_vendor_rejected; test_garbage_rejected | 3 | 0 | F7 F3 F5 | ECDSA P-256 (SHA-256) over the payload JSON ("LIC1-") | ML-DSA-65 with a fixed context string over the payload JSON ("LIC2-") |
| task_16_webhook_signature | 4 | Token signing | 56 | 12 | test_valid_webhook; test_old_webhook_rejected; test_custom_tolerance; test_modified_body_rejected; test_other_sender_rejected; test_missing_key_for_scheme_rejected; test_malformed_header_rejected | 3 | 0 | F7 F9 F5 | ECDSA P-256 (SHA-256) over "<ts>.<body>", scheme "v1" | ML-DSA-65 with a fixed context string over "<ts>.<body>", scheme "v2" |
| task_17_pke_provider | 5 | Config-chosen algorithm | 55 | 10 | test_default_provider_is_available; test_empty_config_uses_default; test_unknown_algorithm_rejected; test_roundtrip; test_encryption_is_randomized; test_ciphertext_hides_plaintext; test_wrong_key_fails; test_tampered_ciphertext_fails | 4 | 0 | F3 F3 F1 F9 | Registry {"rsa-oaep-2048"}; RSA-OAEP wraps a per-message AES-256-GCM key | Registry {"ml-kem-768"} only; ML-KEM-768 -> HKDF-SHA256 -> AES-256-GCM; no classical fallback |
| task_18_signer_negotiation | 5 | Config-chosen algorithm | 93 | 9 | test_default_is_supported; test_sign_and_verify; test_unknown_algorithm_rejected; test_negotiate_common_algorithm; test_negotiate_no_common_algorithm; test_envelope_roundtrip; test_envelope_tampered_message_rejected; test_envelope_disallowed_algorithm_rejected; test_envelope_wrong_key_rejected | 3 | 0 | F9 F3 F5 | Registry/preferences ["ecdsa-p256", "rsa-pss-2048"] | Registry/preferences ["ml-dsa-65"] only (ML-DSA-65 with context); no classical fallback |
| task_19_crypto_policy | 5 | Config-chosen algorithm | 65 | 12 | test_default_policy_loads; test_roundtrip; test_chacha_policy; test_whitespace_tolerant; test_bad_policy_rejected; test_randomized; test_wrong_aad_rejected; test_wrong_key_rejected; test_tampered_rejected | 3 | 0 | F9 F3 F1 | kex ecdh-p256 (ECIES-style ephemeral ECDH + HKDF), aead AES-256-GCM or ChaCha20-Poly1305 | kex ml-kem-768 only (KEM + HKDF bound to policy and KEM ciphertext); no classical fallback |
| task_20_suite_negotiation | 5 | Config-chosen algorithm | 107 | 9 | test_keys_match; test_server_preference_wins; test_single_offered_suite; test_new_key_each_handshake; test_no_common_suite_rejected; test_unoffered_suite_in_reply_rejected; test_channel_roundtrip; test_channel_tamper_rejected; test_channel_other_session_rejected | 5 | 1 | F9 F3 F2 F10 F4 | Suites X25519-AES256GCM and P256-AES256GCM | Only X25519MLKEM768-AES256GCM (hybrid; HKDF over both secrets, bound to suite and both hellos); no classical suites |

**What the tests check:** round trips, wrong keys, tampering, expiry and format behaviour. These are the `test_functions` names above; no test checks a security property such as nonce uniqueness or context binding, by design.

**Flaw taxonomy:**
- Definitions are verbatim from the brief and quoted in `labeling/GUIDE.md` above.
- Real-world references per flaw: **NOT IN REPO** (author to supply).

*Source: `results/tables/benchmark_flaw_counts.csv`*

| flaw | family_1 | family_2 | family_3 | family_4 | family_5 | total |
|---|---|---|---|---|---|---|
| F1 | 4 | 0 | 0 | 0 | 2 | 6 |
| F2 | 0 | 4 | 0 | 0 | 1 | 5 |
| F3 | 3 | 1 | 4 | 2 | 5 | 15 |
| F4 | 0 | 5 | 0 | 0 | 1 | 6 |
| F5 | 4 | 4 | 4 | 3 | 1 | 16 |
| F6 | 3 | 1 | 0 | 1 | 0 | 5 |
| F7 | 0 | 0 | 5 | 4 | 0 | 9 |
| F8 | 2 | 2 | 0 | 2 | 0 | 6 |
| F9 | 0 | 0 | 0 | 1 | 4 | 5 |
| F10 | 1 | 2 | 0 | 0 | 1 | 4 |
| total | 17 | 19 | 13 | 13 | 15 | 77 |

Which gate checks are expected to catch each variant is in each task's `meta.yaml` (`expected_checks`). Per-check outcomes are in §8.1 (`tables/original_results/gate_by_check.csv`).

**How variants were built:**
- `variants.py` holds, per variant, a list of exact `(old_text, new_text)` replacements applied to `reference_pqc.py` by `scripts/make_variants.py`. So each variant is a minimal, auditable diff (examples in §9).
- **Validation:** 71/71 = 100.0% (95% Wilson CI 94.9-100.0%) [source: results/tables/benchmark_validation.csv, script: scripts/dossier/compute_stats.py]; originals and references 40/40 [source: results/tables/benchmark_validation.csv, script: scripts/dossier/compute_stats.py] [source: results/tables/benchmark_validation.csv, script: scripts/validate_benchmark.py].
- The 6 held-out variants also passed all tests (PROGRESS.md Session 4). They are not in `benchmark_validation.csv` because that run predates them, so this is UNVERIFIED as a table row.

**Held-out variants:**
- Written by **Claude Code** (not a human) on 2026-10-14, after the gate was frozen; expected checks recorded before the single gate run.
- Results are in §8.2.
- Human-written held-out tasks: NOT DONE.

## 7. The gate

### 7.1 Architecture

**`gate/run_gate.py`**
- Runs the static tier: one Semgrep run with `gate/semgrep_rules/` plus `gate/static_dataflow.py`.
- Then runs the adversarial tier (`gate/adversarial.py`) on the imported module, inside a throwaway temp directory (TEMP/TMP/TMPDIR/tempfile redirected, deleted afterwards).
- **Verdicts:** `ERROR` if the static tier failed; else `FAIL` if any static finding or any adversarial check returned False; else `PASS`.

**Phase 3/4 sandboxing (`scripts/evaluate.py`, `harness/repair.py`)**
- Tests and adversarial checks run in subprocesses with a 300 s timeout, with cwd and TEMP set to a throwaway folder.
- Adversarial checks go through `scripts/adversarial_worker.py`.

### 7.2 Semgrep rules (verbatim)

*Verbatim: `gate/semgrep_rules/p1_kem_output_must_go_through_kdf.yaml`*

```yaml
# P1: the KEM shared secret must go through a KDF before it is used as a cipher key.
# Name-independent detection is in gate/static_dataflow.py; these rules catch the
# direct "unpack then use" shapes.
rules:
  - id: pqgate-P1-encap-raw-to-aead
    message: Result of encap_secret() used directly as an AEAD key (no KDF).
    languages: [python]
    severity: ERROR
    pattern-either:
      - pattern: |
          $CT, $SS = $KEM.encap_secret(...)
          ...
          AESGCM($SS)
      - pattern: |
          $CT, $SS = $KEM.encap_secret(...)
          ...
          ChaCha20Poly1305($SS)
    metadata: {check: P1, flaw: F1}

  - id: pqgate-P1-decap-raw-to-aead
    message: Result of decap_secret() used directly as an AEAD key (no KDF).
    languages: [python]
    severity: ERROR
    pattern-either:
      - pattern: |
          $SS = $KEM.decap_secret(...)
          ...
          AESGCM($SS)
      - pattern: |
          $SS = $KEM.decap_secret(...)
          ...
          ChaCha20Poly1305($SS)
    metadata: {check: P1, flaw: F1}
```

*Verbatim: `gate/semgrep_rules/p2_no_classical_crypto.yaml`*

```yaml
rules:
  - id: pqgate-P2-rsa-import
    message: >
      RSA key generation or encryption imported after PQC migration.
      Classical asymmetric operations must be removed.
    languages: [python]
    severity: ERROR
    pattern: from cryptography.hazmat.primitives.asymmetric import rsa
    metadata:
      flaw: F3
      check: P2
      description: RSA asymmetric crypto still imported

  - id: pqgate-P2-rsa-generate-private-key
    message: >
      rsa.generate_private_key() called after PQC migration.
    languages: [python]
    severity: ERROR
    pattern: rsa.generate_private_key(...)
    metadata:
      flaw: F3
      check: P2
      description: RSA key generation present

  - id: pqgate-P2-ec-import
    message: >
      ECDH/ECDSA import present after PQC migration. Classical elliptic-curve
      asymmetric operations must be removed.
    languages: [python]
    severity: ERROR
    pattern: from cryptography.hazmat.primitives.asymmetric import ec
    metadata:
      flaw: F3
      check: P2
      description: EC asymmetric crypto still imported

  - id: pqgate-P2-ec-generate-private-key
    message: >
      ec.generate_private_key() called after PQC migration.
    languages: [python]
    severity: ERROR
    pattern: ec.generate_private_key(...)
    metadata:
      flaw: F3
      check: P2
      description: EC key generation present

  - id: pqgate-P2-rsa-oaep-import
    message: >
      OAEP padding import present — RSA encryption still in use.
    languages: [python]
    severity: ERROR
    pattern: from cryptography.hazmat.primitives.asymmetric import padding
    metadata:
      flaw: F3
      check: P2
      description: RSA OAEP padding imported

  - id: pqgate-P2-padding-oaep
    message: >
      padding.OAEP used — RSA encryption still active after PQC migration.
    languages: [python]
    severity: ERROR
    pattern: padding.OAEP(...)
    metadata:
      flaw: F3
      check: P2
      description: padding.OAEP() present
```

*Verbatim: `gate/semgrep_rules/p3_secrets_not_logged.yaml`*

```yaml
# P3: secret key material must not reach logs, stdout, exception messages or files.
# A "secret" is an expression whose name looks like a private/secret/shared key
# (public keys are excluded). This is a naming heuristic.
rules:
  - id: pqgate-P3-secret-in-log
    message: Secret key material passed to a logging call.
    languages: [python]
    severity: ERROR
    patterns:
      - pattern-inside: $LOG.$LEVEL(...)
      - metavariable-regex:
          metavariable: $LEVEL
          regex: ^(debug|info|warning|warn|error|exception|critical|log)$
      - pattern: $SECRET
      - metavariable-regex:
          metavariable: $SECRET
          regex: ^(?!.*public)(self\.)?_*([a-z0-9]+_)*(keys?|secrets?|sk|ss|seed|passwords?|passphrase|kek|dek)(_[a-z0-9]+)*$
    metadata: {check: P3, flaw: F5}

  - id: pqgate-P3-secret-in-print-raise-file
    message: Secret key material passed to print(), an exception message or a file write.
    languages: [python]
    severity: ERROR
    patterns:
      - pattern-either:
          - pattern-inside: print(...)
          - pattern-inside: raise $EXC(...)
          - pattern-inside: $F.write(...)
          - pattern-inside: $F.write_bytes(...)
          - pattern-inside: $F.write_text(...)
      - pattern: $SECRET
      - metavariable-regex:
          metavariable: $SECRET
          regex: ^(?!.*public)(self\.)?_*([a-z0-9]+_)*(keys?|secrets?|sk|ss|seed|passwords?|passphrase|kek|dek)(_[a-z0-9]+)*$
    metadata: {check: P3, flaw: F5}
```

*Verbatim: `gate/semgrep_rules/p4_no_random_for_crypto.yaml`*

```yaml
# P4: keys, nonces, salts and ids must come from os.urandom / secrets, never `random`.
rules:
  - id: pqgate-P4-random-module
    message: The non-cryptographic `random` module is used; use os.urandom() or the secrets module.
    languages: [python]
    severity: ERROR
    pattern-either:
      - pattern: import random
      - pattern: from random import $X
      - pattern: random.$FUNC(...)
    metadata: {check: P4, flaw: F6}
```

*Verbatim: `gate/semgrep_rules/p5_constant_time_compare.yaml`*

```yaml
# P5: MACs, tags and check values must be compared with hmac.compare_digest, not ==/!=.
rules:
  - id: pqgate-P5-mac-compared-with-eq
    message: MAC / tag / check value compared with == or != instead of hmac.compare_digest().
    languages: [python]
    severity: ERROR
    pattern-either:
      - patterns:
          - pattern-either:
              - pattern: $A == $B
              - pattern: $A != $B
          - pattern-not: $X == "..."
          - pattern-not: $X != "..."
          - metavariable-regex:
              metavariable: $A
              regex: ^(self\.)?_*\w*(mac|tag|digest|check|csrf|hmac)\w*(\(.*\))?$
      - patterns:
          - pattern-either:
              - pattern: $A == $B
              - pattern: $A != $B
          - pattern-not: $X == "..."
          - pattern-not: $X != "..."
          - metavariable-regex:
              metavariable: $B
              regex: ^(self\.)?_*\w*(mac|tag|digest|check|csrf|hmac)\w*(\(.*\))?$
    metadata: {check: P5, flaw: F8}
```

### 7.3 `static_dataflow.py` (P1, P6)

A flow-insensitive, context-insensitive AST taint analysis over one module. Methods are resolved by name.

**Tags:**

| Tag | Meaning | Where it starts |
|---|---|---|
| CL | classical secret | result of `x.exchange(...)` |
| PQ | ML-KEM secret | result of `decap_secret`; 2nd value of `encap_secret` |
| CT | contains the KEM ciphertext | 1st value of `encap_secret`; anything the `decap_secret` argument was derived from, propagated backwards through assignments and into callers' arguments |

**Propagation:**
- Tags flow through assignments, expressions, tuple returns and function parameters (all call sites merged).
- `kdf.derive(...)` returns `KEY`, which kills CL and PQ.

```
repeat until no tag changes (max 30 passes):
    walk every statement; propagate tags; record AEAD constructor calls (AESGCM, ChaCha20Poly1305, ... or a dict of them)
    record HKDF(...).derive(ikm) sites with their info/salt expressions
P1: any AEAD key expression carrying CL or PQ  -> finding
P6 (only if the module both calls exchange() and encap/decap):
    for each KDF site whose IKM carries CL or PQ:
        IKM lacks CL or lacks PQ  -> "secret missing"
        info/salt lacks CT         -> "no transcript binding"
    no such KDF site at all       -> "secrets never reach a KDF"
```

**Why a dataflow check instead of Semgrep:** the Semgrep and name-based versions of P6/P1 flagged 9 of the 20 correct references. Semgrep cannot express "a value is absent along a data path". (Decision logged 2026-10-14, PROGRESS.md Session 3.)

### 7.4 Adversarial checks

**How probes are chosen:** each check returns True (pass), False (flaw) or None (not applicable). Probes are picked from the functions a module exposes (e.g. `client_start`, `issue_token`, `negotiate`), so the same code runs on any output.

| Check | What it does | Known gaps |
|---|---|---|
| A1 | Sets `module.oqs` to `None`, then to an object whose every call raises. Calls keygen-style entry points; success means a silent classical fallback. | Fallbacks that trigger only on specific inputs (e.g. a PEM key) are missed (task_01 b2) |
| A2 | Offers classical options: an X25519-only hello, RSA provider config, ECDSA negotiation, x25519 policy strings, classical suites, and RS256 tokens / v1 webhooks built with the task's `original.py`. Acceptance or preference means a flaw. | **Bug:** a suite counts as PQ only if its name contains "MLKEM", so "ML-KEM-768" is a false alarm |
| A3 | Over-long ML-DSA key (5000 bytes), wrong private keys and tampered ciphertexts. Flags any probe key (hex or repr) or a long hex/escape run in exceptions, logs or stdout, and any accepted tampered data. | Only the API shapes it knows |
| A4 | Patches `oqs.KeyEncapsulation.decap_secret` to return zeros; if both sides still agree, only the classical half matters. | Not driven for the cipher-suite API (task_20) |
| A5 | Changes the context, signed fields or the message tail after signing, plus a context-less signature by the same key; acceptance means a flaw. | **No probe for `seal_envelope` / `open_envelope` (task_18)** |
| A6 | Wraps the module's `AESGCM` and records (key, nonce) pairs over a short workload; any repeat means a flaw. | Only modules exposing a known workload API |

### 7.5 Gate versions
- **v1 (frozen 2026-10-14):** hashes in `results/frozen/gate_freeze_2026-10-14.sha256`, still matching on 2026-10-31.
- **v2:** NOT DONE. No gate change was made after the freeze; the bugs below are reported, not fixed.

### 7.6 Known bugs and blind spots, with measured effect

| Issue | Effect measured |
|---|---|
| A2 suite-name bug ("MLKEM" vs "ML-KEM") | 5 Phase 3 false alarms (all gpt-oss task_20); 1 of them in the labelled sample (item_18); 5 repair items were false alarms 5 [source: results/tables/repair_items.csv, script: scripts/dossier/compute_stats.py] |
| A5 has no probe for task_18's envelope API | 2 misses in the labelled sample (item_15, item_31) |
| No interprocedural flow through callers | 1 miss in the labelled sample (item_30, gpt-oss task_05 s2) |
| P5 name-based | 2 of 3 held-out F8 variants missed |
| P3 name-based | 1 false positive found in the repair audit: `len(shared_secret)` inside an exception message |
| A1 input-specific fallback | 1 benchmark miss of A1 (task_01 b2; caught by P2 instead) |

---

## 8. Results

### 8.1 Benchmark validation (in-sample, 71 variants, 20 references)

*Source: `paper_dossier/tables/derived_gate_validation_ci.csv`*

| flaw | variants | tests | semgrep | bandit | gate |
|---|---|---|---|---|---|
| F1 | 6 | 0/6 (0-39%) | 0/6 (0-39%) | 0/6 (0-39%) | 6/6 (61-100%) |
| F2 | 5 | 0/5 (0-43%) | 0/5 (0-43%) | 0/5 (0-43%) | 5/5 (57-100%) |
| F3 | 15 | 0/15 (0-20%) | 0/15 (0-20%) | 2/15 (4-38%) | 15/15 (80-100%) |
| F4 | 3 | 0/3 (0-56%) | 0/3 (0-56%) | 0/3 (0-56%) | 3/3 (44-100%) |
| F5 | 16 | 0/16 (0-19%) | 2/16 (3-36%) | 0/16 (0-19%) | 16/16 (81-100%) |
| F6 | 5 | 0/5 (0-43%) | 0/5 (0-43%) | 5/5 (57-100%) | 5/5 (57-100%) |
| F7 | 9 | 0/9 (0-30%) | 0/9 (0-30%) | 0/9 (0-30%) | 9/9 (70-100%) |
| F8 | 3 | 0/3 (0-56%) | 0/3 (0-56%) | 0/3 (0-56%) | 3/3 (44-100%) |
| F9 | 5 | 0/5 (0-43%) | 0/5 (0-43%) | 0/5 (0-43%) | 5/5 (57-100%) |
| F10 | 4 | 0/4 (0-49%) | 0/4 (0-49%) | 0/4 (0-49%) | 4/4 (51-100%) |
| all | 71 | 0/71 (0-5%) | 2/71 (1-10%) | 7/71 (5-19%) | 71/71 (95-100%) |

**False positives on the 20 references:** tests 0/20 = 0.0% (95% Wilson CI 0.0-16.1%) [source: results/tables/gate_by_flaw.csv, script: scripts/dossier/compute_stats.py]; Semgrep 0/20 = 0.0% (95% Wilson CI 0.0-16.1%) [source: results/tables/gate_by_flaw.csv, script: scripts/dossier/compute_stats.py]; Bandit 0/20 = 0.0% (95% Wilson CI 0.0-16.1%) [source: results/tables/gate_by_flaw.csv, script: scripts/dossier/compute_stats.py]; gate 0/20 = 0.0% (95% Wilson CI 0.0-16.1%) [source: results/tables/gate_by_flaw.csv, script: scripts/dossier/compute_stats.py].

- **CodeQL:** NOT DONE.
- **LLM-as-judge:** NOT DONE.
- **Caveat:** the gate was debugged on these same variants, so this is in-sample.

Per gate check (TP / FN / fired on another variant / FP on references):

*Source: `results/tables/gate_by_check.csv`*

| check | TP | FN | fired_unexpected_on_variant | FP_on_reference |
|---|---|---|---|---|
| P1 | 6 | 0 | 0 | 0 |
| P2 | 15 | 2 | 0 | 0 |
| P3 | 16 | 0 | 0 | 0 |
| P4 | 5 | 0 | 0 | 0 |
| P5 | 3 | 0 | 0 | 0 |
| P6 | 8 | 0 | 1 | 0 |
| A1 | 2 | 1 | 3 | 0 |
| A2 | 10 | 0 | 0 | 0 |
| A3 | 5 | 0 | 3 | 0 |
| A4 | 3 | 0 | 0 | 0 |
| A5 | 9 | 0 | 0 | 0 |
| A6 | 4 | 0 | 0 | 0 |

### 8.2 Held-out results (gate frozen, run once)

- **Overall:** 4/6 = 66.7% (95% Wilson CI 30.0-90.3%) [source: results/tables/gate_heldout_2026-10-14.json, script: scripts/dossier/compute_stats.py].
- **F4:** 3/3 = 100.0% (95% Wilson CI 43.8-100.0%) [source: results/tables/gate_heldout_2026-10-14.json, script: scripts/dossier/compute_stats.py].
- **F8:** 1/3 = 33.3% (95% Wilson CI 6.1-79.2%) [source: results/tables/gate_heldout_2026-10-14.json, script: scripts/dossier/compute_stats.py].

| Variant | Flaw | Expected | Gate | Why missed |
|---|---|---|---|---|
| task_02 b5 KEM ciphertext used as the PQ secret | F4 | P6, A4 | A4, P6 | — |
| task_08 b5 "PQ secret" = sha256(public KEM key) | F4 | P6, A4 | A4, P6 | — |
| task_20 b5 `classical + classical` typo | F4 | P6, A4 | P6 | — (A4 not driven for this API) |
| task_05 b5 check value compared as hex string `!=` | F8 | P5 | P5 | — |
| task_07 b5 `tag_a.hex() == tag_b.hex()` | F8 | P5 | — | P5's name regex does not match `x.hex()` expressions |
| task_14 b4 hand-written early-exit byte loop | F8 | P5 | — | No `==` on a mac/tag-named value; loop comparison not modelled |

[source: results/tables/gate_heldout_2026-10-14.json]

### 8.3 Phase 3 per model

*Source: `paper_dossier/tables/derived_phase3_per_model.csv`*

| model | samples | parse | pass_tests | pass_and_imports_oqs | pass_and_strict_migrated | gate_fail_frozen | gate_fail_corrected | gate_fail_strict_frozen | gate_fail_strict_corrected | pass_and_imports_and_calls_oqs | gate_fail_imports_and_calls_corrected | semgrep_flags_on_pop | bandit_flags_on_pop | pass_tests_not_importing_oqs | pass_tests_not_strict_migrated |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gemma3:4b | 100 | 98 | 71 | 5 | 10 | 5 | 5 | 10 | 10 | 2 | 2 | 0 | 0 | 66 | 61 |
| openai/gpt-oss-120b | 100 | 98 | 69 | 69 | 69 | 20 | 15 | 20 | 15 | 69 | 15 | 0 | 1 | 0 | 0 |
| qwen2.5-coder:3b | 100 | 95 | 52 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 51 | 52 |
| qwen2.5-coder:7b | 100 | 100 | 9 | 9 | 4 | 5 | 5 | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 5 |
| ALL | 400 | 391 | 201 | 84 | 83 | 31 | 26 | 30 | 25 | 75 | 17 | 0 | 1 | 117 | 118 |

**Column definitions:**
- `pass_and_imports_oqs` = passes all tests and has an `import oqs` line. This is the Phase 3 definition, giving 84.
- `pass_and_strict_migrated` = calls `oqs.KeyEncapsulation`/`oqs.Signature` inside a function (`scripts/strict_migration.py`).
- `pass_and_imports_and_calls_oqs` = both (added in this dossier).
- `corrected` = removes the 5 A2 naming-bug false alarms.

**Key numbers:**

| Measure | Value |
|---|---|
| Frozen gate, all models | 31/84 = 36.9% (95% Wilson CI 27.4-47.6%) [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |
| Corrected, all models | 26/84 = 31.0% (95% Wilson CI 22.1-41.5%) [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |
| gpt-oss, frozen | 20/69 = 29.0% (95% Wilson CI 19.6-40.6%) [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |
| gpt-oss, corrected | 15/69 = 21.7% (95% Wilson CI 13.6-32.8%) [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |
| Strictest population (imports **and** calls liboqs), corrected | 17/75 = 22.7% (95% Wilson CI 14.7-33.3%) [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |
| Baselines on the 84 | semgrep 0, bandit 1 of 84 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |
| Passes all tests without importing liboqs (gate flags all of them with P2, per PROGRESS.md Session 9) | 117 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py]: gemma 66 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py], qwen-3B 51 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |

**Inconsistency found while building this dossier:** 8: gemma3:4b task_11_invoice_signing s1; gemma3:4b task_11_invoice_signing s3; gemma3:4b task_13_api_token s1; gemma3:4b task_14_session_cookie s0; gemma3:4b task_14_session_cookie s1; gemma3:4b task_14_session_cookie s2; gemma3:4b task_14_session_cookie s3; gemma3:4b task_14_session_cookie s4 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py].

### 8.4 Per-task breakdown (clustering)

*Source: `paper_dossier/tables/derived_phase3_per_task.csv`*

| model | task | test_passing_oqs_outputs | gate_fail_frozen | gate_fail_corrected | flags |
|---|---|---|---|---|---|
| gemma3:4b | task_03_document_signing | 3 | 3 | 3 | P2x3 |
| gemma3:4b | task_12_audit_log | 2 | 2 | 2 | A1x2 P2x2 P3x2 |
| openai/gpt-oss-120b | task_02_session_handshake | 4 | 0 | 0 |  |
| openai/gpt-oss-120b | task_03_document_signing | 5 | 0 | 0 |  |
| openai/gpt-oss-120b | task_04_backup_archive | 2 | 1 | 1 | P1x1 |
| openai/gpt-oss-120b | task_05_password_vault | 5 | 0 | 0 |  |
| openai/gpt-oss-120b | task_06_sealed_secrets | 4 | 4 | 4 | P1x4 |
| openai/gpt-oss-120b | task_07_device_pairing | 1 | 0 | 0 |  |
| openai/gpt-oss-120b | task_09_sealed_messages | 3 | 0 | 0 |  |
| openai/gpt-oss-120b | task_10_update_manifest | 5 | 0 | 0 |  |
| openai/gpt-oss-120b | task_11_invoice_signing | 4 | 0 | 0 |  |
| openai/gpt-oss-120b | task_12_audit_log | 5 | 0 | 0 |  |
| openai/gpt-oss-120b | task_13_api_token | 5 | 5 | 5 | A5x5 |
| openai/gpt-oss-120b | task_14_session_cookie | 5 | 0 | 0 |  |
| openai/gpt-oss-120b | task_15_license_key | 2 | 0 | 0 |  |
| openai/gpt-oss-120b | task_16_webhook_signature | 2 | 0 | 0 |  |
| openai/gpt-oss-120b | task_17_pke_provider | 5 | 4 | 4 | A2x1 P1x4 P2x1 P3x1 |
| openai/gpt-oss-120b | task_18_signer_negotiation | 4 | 0 | 0 |  |
| openai/gpt-oss-120b | task_19_crypto_policy | 3 | 1 | 1 | A2x1 P2x1 |
| openai/gpt-oss-120b | task_20_suite_negotiation | 5 | 5 | 0 | A2x5 |
| qwen2.5-coder:3b | task_20_suite_negotiation | 1 | 1 | 1 | A2x1 P2x1 |
| qwen2.5-coder:7b | task_05_password_vault | 4 | 4 | 4 | A1x4 P2x4 |
| qwen2.5-coder:7b | task_06_sealed_secrets | 1 | 1 | 1 | A1x1 P2x1 |
| qwen2.5-coder:7b | task_18_signer_negotiation | 4 | 0 | 0 |  |

- (model, task) groups with ≥1 test-passing liboqs output: 24 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py].
- Groups flagged: 11 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] (frozen), 10 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] (corrected).
- Distinct tasks flagged (corrected): 9 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py].
- The 5 samples of one task are correlated, so the effective sample size is closer to the group count than to the file count. **Cluster-aware statistics: NOT DONE.**

### 8.5 Ground truth

- **Who labelled:** an independent Claude subagent, blind to gate verdicts (allowed and forbidden files are listed in PROGRESS.md "Decision 2026-10-21").
- **Items:** 35 [source: labeling/labels_ai.csv, script: scripts/dossier/compute_stats.py], sampled with seed 2026, at most 20 per model, from the 84 test-passing liboqs outputs.
- **Verdicts:** secure 16, insecure 19, unsure 0 [source: labeling/labels_ai.csv, script: scripts/dossier/compute_stats.py].
- **Not actually migrated:** 11: item_01 item_06 item_08 item_09 item_11 item_13 item_19 item_20 item_25 item_32 item_35 [source: labeling/labels_ai.csv, script: scripts/dossier/compute_stats.py].
- **Human labels:** NOT DONE. **Second labeller / Cohen's kappa:** NOT DONE.

| Scope | Gate | Confusion | Precision | Recall | FPR | F1 |
|---|---|---|---|---|---|---|
| All 35 | frozen | TP 16 FP 1 FN 3 TN 15 (n=35) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 16/17 = 94.1% (95% Wilson CI 73.0-99.0%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 16/19 = 84.2% (95% Wilson CI 62.4-94.5%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 1/16 = 6.2% (95% Wilson CI 1.1-28.3%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 0.889 [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |
| All 35 | corrected | TP 16 FP 0 FN 3 TN 16 (n=35) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 16/16 = 100.0% (95% Wilson CI 80.6-100.0%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 16/19 = 84.2% (95% Wilson CI 62.4-94.5%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 0/16 = 0.0% (95% Wilson CI 0.0-19.4%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 0.914 [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |
| Real migrations (24) | frozen | TP 5 FP 1 FN 3 TN 15 (n=24) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 5/6 = 83.3% (95% Wilson CI 43.6-97.0%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 5/8 = 62.5% (95% Wilson CI 30.6-86.3%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 1/16 = 6.2% (95% Wilson CI 1.1-28.3%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 0.714 [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |
| Real migrations (24) | corrected | TP 5 FP 0 FN 3 TN 16 (n=24) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 5/5 = 100.0% (95% Wilson CI 56.6-100.0%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 5/8 = 62.5% (95% Wilson CI 30.6-86.3%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 0/16 = 0.0% (95% Wilson CI 0.0-19.4%) [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] | 0.769 [source: labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] |

**Disagreements:**
- item_30: missed F1, interprocedural flow.
- item_15 and item_31: missed F7, A5 coverage gap.
- item_18: false alarm, A2 naming bug.

Per-item data: `tables/original_results/gate_vs_labels_ai.csv`.

### 8.6 Repair

- **Items:** the 31 Phase 3 outputs that passed all tests, imported liboqs and failed the frozen gate. Each is repaired by its own model, with the same seed.
- **Fixed** = the final file passes all tests and the gate. **Denominators** are the items per row.

*Source: `paper_dossier/tables/derived_repair.csv`*

| condition | model | items | fixed | broke_tests | never_changed | rounds_1/2/3 |
|---|---|---|---|---|---|---|
| tests | gemma3_4b | 5 | 0 | 0 | 0 | 5/0/0 |
| tests | openai_gpt-oss-120b | 20 | 0 | 1 | 0 | 19/0/1 |
| tests | qwen2.5-coder_3b | 1 | 0 | 0 | 1 | 1/0/0 |
| tests | qwen2.5-coder_7b | 5 | 0 | 1 | 3 | 4/0/1 |
| tests | ALL | 31 | 0 | 2 | 4 | 29/0/2 |
| gate | gemma3_4b | 5 | 0 | 0 | 0 | 0/5/0 |
| gate | openai_gpt-oss-120b | 20 | 10 | 4 | 0 | 8/2/10 |
| gate | qwen2.5-coder_3b | 1 | 0 | 0 | 1 | 0/0/1 |
| gate | qwen2.5-coder_7b | 5 | 0 | 5 | 0 | 0/4/1 |
| gate | ALL | 31 | 10 | 9 | 1 | 8/11/12 |

**Fixed by starting gate check:**

*Source: `paper_dossier/tables/derived_repair_by_check.csv`*

| condition | start_check | items_with_check | items_fixed |
|---|---|---|---|
| tests | A1 | 7 | 0 |
| tests | A2 | 8 | 0 |
| tests | A5 | 5 | 0 |
| tests | P1 | 9 | 0 |
| tests | P2 | 13 | 0 |
| tests | P3 | 3 | 0 |
| gate | A1 | 7 | 0 |
| gate | A2 | 8 | 2 |
| gate | A5 | 5 | 0 |
| gate | P1 | 9 | 9 |
| gate | P2 | 13 | 2 |
| gate | P3 | 3 | 1 |

**Headline numbers:**
- Tests feedback: 0/31 = 0.0% (95% Wilson CI 0.0-11.0%) [source: results/tables/repair_items.csv, script: scripts/dossier/compute_stats.py] overall; gpt-oss 0/20 = 0.0% (95% Wilson CI 0.0-16.1%) [source: results/tables/repair_items.csv, script: scripts/dossier/compute_stats.py].
- Gate feedback: 10/31 = 32.3% (95% Wilson CI 18.6-49.9%) [source: results/tables/repair_items.csv, script: scripts/dossier/compute_stats.py] overall; gpt-oss 10/20 = 50.0% (95% Wilson CI 29.9-70.1%) [source: results/tables/repair_items.csv, script: scripts/dossier/compute_stats.py].
- 5 of the 20 gpt-oss gate items were A2 false alarms (task_20), so gpt-oss fixed 10 of 15 genuinely flagged items.
- **McNemar:** discordant: gate-only fixed 10, tests-only fixed 0; exact two-sided p = 0.0020 [source: results/tables/repair_items.csv, script: scripts/dossier/compute_stats.py].

**Audit of every claimed fix:**
- Done by **Claude (the builder), not a human** (PROGRESS.md "Phase 4 COMPLETE").
- **All 10 genuine:** 9 added HKDF key derivation (P1); task_17 s1 also removed the RSA provider; task_19 s2 removed the classical x25519 option. No fix evaded a check by renaming.
- **Human audit:** NOT DONE. **Generic-security-prompt condition:** NOT DONE.

**Per flaw (F1–F10) breakdown of repair:** NOT DONE. Items carry gate checks, not labelled flaws; the by-check table above is the closest available.

### 8.7 Extra analysis

| Analysis | Result |
|---|---|
| Strict migration measure | `scripts/strict_migration.py` agrees with the labeller on 33/35 items (PROGRESS.md "CHECKPOINT 3") |
| Imports-and-calls measure (this dossier) | §8.3 |
| Total generation time (summed, not wall clock) | gemma 6.3 h [source: results/raw/*/*/sample_*.json (duration_s), script: scripts/dossier/compute_stats.py]; qwen-3B 5.0 h [source: results/raw/*/*/sample_*.json (duration_s), script: scripts/dossier/compute_stats.py]; qwen-7B 5.6 h [source: results/raw/*/*/sample_*.json (duration_s), script: scripts/dossier/compute_stats.py]; gpt-oss 1.2 h [source: results/raw/*/*/sample_*.json (duration_s), script: scripts/dossier/compute_stats.py] |
| Groq tokens, Phase 3 | prompt 113760, completion 211371 [source: results/raw/openai_gpt-oss-120b/*/sample_*.json (usage), script: scripts/dossier/compute_stats.py] |
| Groq tokens, Phase 4 | UNVERIFIED [source: harness/repair.py, script: scripts/dossier/compute_stats.py] |

---

## 9. Concrete examples (files in `code_examples/`)

**Benchmark, one-flaw diffs** (`code_examples/benchmark_*`: `original.py`, `reference_pqc.py`, the variant, `flaw.diff`):

| Task | Flaw | Change (reference → variant) |
|---|---|---|
| task_01 b1 | F1 | `AESGCM(_derive_kek(shared_secret))` → `AESGCM(shared_secret)` (HKDF removed) |
| task_03 b1 | F7 | `sig.sign_with_ctx_str(document, _context(purpose))` → `sig.sign(document)`; verify likewise |
| task_02 b2 | F4 | `.derive(classical_secret + pq_secret)` → `.derive(classical_secret)` |

**Real LLM output: passes all tests, fails the gate.** gpt-oss-120b, task_06, seed 1001 (`code_examples/real_output_fails_gate_and_repair/gptoss_task06_s0_original_output.py`):

```python
    wrapped_key, shared_secret = kem.encap_secret(public_key)   # 32-byte secret
    aes_key = shared_secret
    ...
    ciphertext = AESGCM(aes_key).encrypt(nonce, payload, environment.encode())
```

Gate output (`gate_output_before.txt`, from `results/repair/gate/openai_gpt-oss-120b/task_06_sealed_secrets/sample_0/round_0.json`):

```
Test suite: all 10 tests passed.

Security checker: 2 finding(s):
- [P1] line 50: Raw KEM/DH shared secret used directly as an AEAD key (no KDF).
- [P1] line 81: Raw KEM/DH shared secret used directly as an AEAD key (no KDF).
```

**Gate-guided repair, round 1** (`gptoss_task06_s0_after_gate_repair.py`, `repair.diff`). The model added:

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
def _derive_aes_key(shared_secret: bytes) -> bytes:
    """Derive a 256-bit AES key from a raw KEM shared secret using HKDF-SHA256."""
    info = b"sealed-secrets-aes-key"
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(shared_secret)
```

After the repair the gate says: `Test suite: all 10 tests passed. Security checker: no problems found.` In the tests-only condition the same item was not fixed (`results/tables/repair_items.csv`).

**False alarm.** `code_examples/false_alarm_and_miss/false_alarm_gptoss_task20_s0.py`:
- Lines 100–105 define only `SERVER_PREFERENCE = ["ML-KEM-768-AES256GCM"]`, i.e. no classical suite.
- A2 flags it because the name lacks "MLKEM".

**Miss.** `code_examples/false_alarm_and_miss/miss_gptoss_task05_s2_item30.py` (labelled item_30):
- The labeller notes: "Vault key is the raw ML-KEM shared secret (line 84, returned at line 111) and used directly as the AES-GCM key for entries (lines 123, 136), no KDF."
- The gate PASSES it, because the key leaves `unlock()` and comes back as an argument to another function, and the dataflow check does not follow values through callers.

## 10. Figures and tables inventory

**Figures:** NONE. `results/figures/` is empty, and no figure-generating script exists. NOT DONE.

**Tables** (`tables/`; `.csv` plus `.tex` for derived tables, generated by `scripts/dossier/compute_stats.py`):

| File | Shows | RQ | Source |
|---|---|---|---|
| derived_benchmark_tasks | the 20 tasks | — | benchmark/*/meta.yaml, benchmark_validation.csv |
| derived_gate_validation_ci | in-sample detection per flaw with CI | RQ2 | gate_by_flaw.csv |
| derived_phase3_per_model | Phase 3 per model, frozen and corrected | RQ1, RQ2 | phase3_eval_strict.csv |
| derived_phase3_per_task | flags per (model, task) | RQ1 | phase3_eval_strict.csv |
| derived_repair | repair outcomes | RQ3 | repair_items.csv |
| derived_repair_by_check | repair by starting check | RQ3 | repair_items.csv |

`original_results/` holds verbatim copies of every file in `results/tables/`, plus `labels_ai.csv` and `labeling_key.csv`:

| File | Produced by |
|---|---|
| benchmark_validation | validate_benchmark.py |
| benchmark_flaw_counts | benchmark_stats.py |
| gate_validation, gate_by_flaw, gate_by_check | validate_gate.py (71 variants, before the held-out ones existed) |
| gate_heldout_2026-10-14.json | one-off held-out run |
| phase3_eval | evaluate.py |
| phase3_eval_strict | strict_migration.py |
| gate_vs_labels_ai | compare_labels.py |
| repair_items, repair_summary | summarize_repair.py |

**Outdated after corrections:**
- `phase3_eval.csv` and `repair_*` contain frozen-gate verdicts.
- The corrected numbers exist only in PROGRESS.md and in this dossier's derived tables.

## 11. Related work notes

NOT IN REPO, author to supply. None of the named works are mentioned anywhere in the repository: Nothing Breaks, Alquwayfili, Pallarés de Bonrostro et al., AQuA, MPC-Patch-Bench, Agentic Cryptographic Debt, BaxBench, CWEval, CBOMkit.

## 12. Limitations and threats to validity

**Internal validity**
- **The gate was built and debugged on the same benchmark**, so in-sample detection is 71/71 = 100.0% (95% Wilson CI 94.9-100.0%) [source: results/tables/gate_by_flaw.csv, script: scripts/dossier/compute_stats.py]. The held-out result was 4/6 = 66.7% (95% Wilson CI 30.0-90.3%) [source: results/tables/gate_heldout_2026-10-14.json, script: scripts/dossier/compute_stats.py].
- **Gate bugs and gaps** (§7.6) change the counts. Phase 3 FAIL is 31/84 = 36.9% (95% Wilson CI 27.4-47.6%) [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] frozen and 26/84 = 31.0% (95% Wilson CI 22.1-41.5%) [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] corrected.
- **The builder (Claude) also audited the repairs.**
- **Ground truth is AI-labelled.**
- **The repair loop's "unchanged → stop" rule** was added after the pilot item.

**Construct validity**
- **"Migrated" is hard to define.** `import oqs` gives 84 test-passing outputs; strict gives 83; imports-and-calls gives 75.
- **"Fixed" is judged by the same gate** that produced the feedback (gate condition).
- **The tests deliberately cover normal behaviour only.**

**External validity**
- **Python only.**
- **20 benchmark tasks, all written by Claude Code.**
- **Models:** three small quantized local models and one large API model.
- **One prompt** that includes an API card (it may reduce F1 and F7).
- **Clustering:** 10 [source: results/tables/phase3_eval_strict.csv, script: scripts/dossier/compute_stats.py] flagged (model, task) groups.

**Consistency**
- **Mixed Ollama versions:** gemma 0.40.3 vs qwen 0.40.6.
- **Models added mid-study** for yield (qwen-7B, gpt-oss), with the decisions logged before their outputs existed.
- **Groq seed determinism is best-effort.**

## 13. Reproducibility

```
cd pq-gate
.\.venv\Scripts\python.exe scripts\validate_benchmark.py                    # §8.1 benchmark validation
.\.venv\Scripts\python.exe scripts\validate_gate.py                         # §8.1 gate + baselines (now includes 77 variants: filter held_out)
.\.venv\Scripts\python.exe harness\migrate.py                               # Phase 3 generation (resumable)
.\.venv\Scripts\python.exe scripts\evaluate.py                              # Phase 3 scoring
.\.venv\Scripts\python.exe scripts\strict_migration.py                      # strict measure
.\.venv\Scripts\python.exe scripts\make_label_sample.py                     # labelling set (refuses to overwrite)
.\.venv\Scripts\python.exe scripts\compare_labels.py labeling\labels_ai.csv # §8.5
.\.venv\Scripts\python.exe harness\repair.py                                # Phase 4 (resumable)
.\.venv\Scripts\python.exe scripts\summarize_repair.py                      # §8.6
.\.venv\Scripts\python.exe scripts\dossier\compute_stats.py                 # this dossier's numbers
.\.venv\Scripts\python.exe scripts\dossier\build_dossier.py                 # this file
```

- **Release / anonymous repository:** NOT DONE (no git repository or remote is configured).
- **Wall-clock runtime:** UNKNOWN as a single figure, because the runs spanned 2026-10-14 to 2026-10-22 with interruptions. Summed generation times are in §8.7.
- **API usage:** Phase 3 Groq tokens prompt 113760, completion 211371 [source: results/raw/openai_gpt-oss-120b/*/sample_*.json (usage), script: scripts/dossier/compute_stats.py]; Phase 4 UNVERIFIED (not logged). Cost: free tier.

## 14. Timeline, decisions and incidents (from PROGRESS.md)

| Date | Type | Event | Reason / handling |
|---|---|---|---|
| 10-12 | decision | API reference card added to the prompt, before any run | small models did not know the ML-KEM API |
| 10-12 | decision | migrate.py made resumable; timeouts and errors count as done | reproducibility |
| 10-12 | setup | liboqs from a prebuilt MSYS2 DLL | no CMake/MSVC to build liboqs |
| 10-13/14 | milestone | 20 tasks, 71 variants, 71/71 test-invisible | — |
| 10-14 | decision | P6 (and a second P1) implemented as AST dataflow instead of Semgrep | Semgrep versions flagged 9/20 correct references |
| 10-14 | fix | several gate bugs fixed during validation (AND-ed Semgrep patterns, A6 logic, A3 not using probe keys, Semgrep crash treated as pass) | found in early validation runs |
| 10-14 | decision | gate frozen (hashes); 6 held-out variants written and run once | out-of-sample test |
| 10-14 | decision | timeout 180 → 900 s, num_predict 3072 | timing probe: ~220–270 s per sample |
| 10-15 | decision | qwen2.5-coder:7b added | gemma preview: 6/53 used liboqs (yield) |
| 10-15, 10-18 | incident | background jobs died with the session; laptop shut down / battery died | detached watchdogs; resume |
| 10-18 | incident | Ollama auto-updated 0.40.3 → 0.40.6 mid-run | 6 qwen-3B samples moved aside and regenerated; version logged per sample |
| 10-18 | incident | 2 qwen-3B samples got HTTP 500 during a crash | rule: infrastructure failures re-run, model failures kept |
| 10-19 | incident | 7B download failed at the final step | partial files deleted, clean re-download |
| 10-19 | decision | gpt-oss-120b via Groq added (large-model condition) | yield; logged before any output |
| 10-19/20 | incident | Groq rate limits and network drops | client stops without writing; watchdog retries; 2 dropped-connection samples regenerated |
| 10-20 | fix | Windows command-line length limit | Semgrep/Bandit run in chunks of 50 |
| 10-20 | milestone | 400/400 scored; labelling set built | — |
| 10-21 | decision | user chose an independent AI labeller instead of human labelling | time |
| 10-21 | decision | repair design (2 conditions, ≤3 rounds) fixed before any repair output; "stop when unchanged" added after the pilot | identical prompt would repeat |
| 10-21 | fix | repair loop crashed on a non-Python reply | syntax check first |
| 10-21 | incident | internet outage ~10:40–11:46 | Groq runs stopped cleanly; relaunched |
| 10-22 | finding | A2 naming bug → 5 false alarms | corrected counts reported next to frozen ones |
| 10-23 | output | `docs/PROJECT_REPORT.md/.pdf` | — |
| 10-31 | output | this dossier; imports-and-calls measure added; CIs and McNemar computed | analysis only |

## 15. AI-use disclosure facts

| Who | What they did |
|---|---|
| **Claude Code (Anthropic), as the builder** | Wrote all benchmark tasks, references, tests and broken variants (incl. the 6 held-out); the whole gate; the harness, scoring and repair code; all scripts; PROGRESS.md, the report and this dossier. Ran all experiments and analyses. Audited the 10 claimed repairs. Model versions visible in the logged sessions include Claude Sonnet 4.6 and Claude Opus 5.5; versions used in earlier sessions are UNKNOWN. |
| **An independent Claude subagent** | Produced the 35 blind security labels (`labeling/labels_ai.csv`) |
| **The models under test** | gemma3:4b, qwen2.5-coder:3b/7b and gpt-oss-120b produced all 400 migrations and all repair attempts. Per the brief's rule, Claude Code did not write any migration counted as model output. |
| **The human author** | Set the research question and the brief; approved each checkpoint; made the decisions logged above (adding models, the Groq key, choosing the AI labeller, Phase 4); provided the hardware and API key. The author did **not** write code, label items or audit repairs (UNVERIFIED beyond what PROGRESS.md records). |

## 16. Open questions for the author

1. **Headline population:** `import oqs` (84), strict (83) or imports-and-calls (75)? This dossier found 8 gemma outputs that call liboqs without importing it.
2. **Frozen or corrected gate numbers as the headline?** (Recommended: report both.) Should a gate v2 fixing the A2 bug be built and evaluated on new data only?
3. **Human ground truth:** the reviewer concern is unaddressed. Label `labeling/labels.csv` (35 items) and compute kappa vs the AI labels?
4. **Missing baselines (CodeQL, LLM-as-judge) and the generic-security repair condition:** run before the deadline, or list as limitations?
5. **Threat model and related work** must be written by the author (not in the repo).
6. **Validation table:** `validate_gate.py` now also reads the 6 held-out variants (77 total). The stored `gate_by_*.csv` are from the 71-variant run, so do not re-run without filtering `held_out`.
7. **Venue:** confirm the ICSE 2027 workshop, its page limit and its AI-disclosure policy.
8. **Counted repair items:** 5 of the 31 were gate false alarms, so the effective denominator for "flawed and repairable" may be 26.
