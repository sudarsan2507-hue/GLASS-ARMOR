# PQ-GATE - Paper Dossier

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
| 14 | Framing | NOT DONE | Paper not written | - |
| 15 | Venue check | NOT DONE | Venue named in the brief only (ICSE 2027 workshop); call for papers / page limits not checked | - |

---

## 1. One-paragraph summary

We test whether LLM-made migrations from classical cryptography to post-quantum cryptography (ML-KEM, ML-DSA via liboqs) can pass all functional tests while being insecure. A benchmark of <<num bench_tasks>> Python tasks contains <<num bench_variants_total>> broken migrations. All 71 original variants are test-invisible: <<num bench_test_invisible>>. A PQC-aware gate (Semgrep rules, an AST dataflow checker and behavioural attacks) flags <<num val_gate_detect>> of them in-sample, with <<num val_gate_fp>> false alarms on correct references. On the same variants: tests <<num val_tests_detect>>, default Semgrep <<num val_semgrep_detect>>, Bandit <<num val_bandit_detect>>. On 6 held-out variants the gate catches <<num heldout_caught>>. Four models produced 400 migrations, and <<num p3_ALL_pass>> pass all tests. Of the 84 test-passing outputs that import liboqs, the gate fails <<num p3_ALL_fail_frozen>> (frozen gate), or <<num p3_ALL_fail_corrected>> after correcting a naming bug. Baselines on the same 84: <<num p3_ALL_baselines>>. Separately, <<num p3_ALL_classical_pass>> outputs pass all tests without even importing liboqs. Against blind AI labels on real migrations, the gate's recall is <<num lab_real_frozen_recall>> and precision <<num lab_real_frozen_precision>> (frozen). In a repair loop, test feedback fixed <<num rep_tests_ALL_fixed>> items and gate feedback fixed <<num rep_gate_ALL_fixed>>; McNemar <<num rep_mcnemar>>.

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

<<include requirements.txt>>

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

<<include config.yaml>>

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

<<include labeling/GUIDE.md>>

---

## 6. Benchmark

- **Tasks:** <<num bench_tasks>>.
- **Original files:** <<num bench_orig_lines_min_max>> lines each.
- **Functional tests:** <<num bench_tests_total>> in total.
- **Broken variants:** <<num bench_variants_total>>, of which held-out: <<num bench_variants_heldout>>.

<<table paper_dossier/tables/derived_benchmark_tasks.csv>>

**What the tests check:** round trips, wrong keys, tampering, expiry and format behaviour. These are the `test_functions` names above; no test checks a security property such as nonce uniqueness or context binding, by design.

**Flaw taxonomy:**
- Definitions are verbatim from the brief and quoted in `labeling/GUIDE.md` above.
- Real-world references per flaw: **NOT IN REPO** (author to supply).

<<table results/tables/benchmark_flaw_counts.csv>>

Which gate checks are expected to catch each variant is in each task's `meta.yaml` (`expected_checks`). Per-check outcomes are in §8.1 (`tables/original_results/gate_by_check.csv`).

**How variants were built:**
- `variants.py` holds, per variant, a list of exact `(old_text, new_text)` replacements applied to `reference_pqc.py` by `scripts/make_variants.py`. So each variant is a minimal, auditable diff (examples in §9).
- **Validation:** <<num bench_test_invisible>>; originals and references <<num bench_orig_ref_pass>> [source: results/tables/benchmark_validation.csv, script: scripts/validate_benchmark.py].
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

<<include gate/semgrep_rules/p1_kem_output_must_go_through_kdf.yaml>>

<<include gate/semgrep_rules/p2_no_classical_crypto.yaml>>

<<include gate/semgrep_rules/p3_secrets_not_logged.yaml>>

<<include gate/semgrep_rules/p4_no_random_for_crypto.yaml>>

<<include gate/semgrep_rules/p5_constant_time_compare.yaml>>

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
| A2 suite-name bug ("MLKEM" vs "ML-KEM") | 5 Phase 3 false alarms (all gpt-oss task_20); 1 of them in the labelled sample (item_18); 5 repair items were false alarms <<num rep_task20_items>> |
| A5 has no probe for task_18's envelope API | 2 misses in the labelled sample (item_15, item_31) |
| No interprocedural flow through callers | 1 miss in the labelled sample (item_30, gpt-oss task_05 s2) |
| P5 name-based | 2 of 3 held-out F8 variants missed |
| P3 name-based | 1 false positive found in the repair audit: `len(shared_secret)` inside an exception message |
| A1 input-specific fallback | 1 benchmark miss of A1 (task_01 b2; caught by P2 instead) |

---

## 8. Results

### 8.1 Benchmark validation (in-sample, 71 variants, 20 references)

<<table paper_dossier/tables/derived_gate_validation_ci.csv>>

**False positives on the 20 references:** tests <<num val_tests_fp>>; Semgrep <<num val_semgrep_fp>>; Bandit <<num val_bandit_fp>>; gate <<num val_gate_fp>>.

- **CodeQL:** NOT DONE.
- **LLM-as-judge:** NOT DONE.
- **Caveat:** the gate was debugged on these same variants, so this is in-sample.

Per gate check (TP / FN / fired on another variant / FP on references):

<<table results/tables/gate_by_check.csv>>

### 8.2 Held-out results (gate frozen, run once)

- **Overall:** <<num heldout_caught>>.
- **F4:** <<num heldout_F4>>.
- **F8:** <<num heldout_F8>>.

| Variant | Flaw | Expected | Gate | Why missed |
|---|---|---|---|---|
| task_02 b5 KEM ciphertext used as the PQ secret | F4 | P6, A4 | A4, P6 | - |
| task_08 b5 "PQ secret" = sha256(public KEM key) | F4 | P6, A4 | A4, P6 | - |
| task_20 b5 `classical + classical` typo | F4 | P6, A4 | P6 | - (A4 not driven for this API) |
| task_05 b5 check value compared as hex string `!=` | F8 | P5 | P5 | - |
| task_07 b5 `tag_a.hex() == tag_b.hex()` | F8 | P5 | - | P5's name regex does not match `x.hex()` expressions |
| task_14 b4 hand-written early-exit byte loop | F8 | P5 | - | No `==` on a mac/tag-named value; loop comparison not modelled |

[source: results/tables/gate_heldout_2026-10-14.json]

### 8.3 Phase 3 per model

<<table paper_dossier/tables/derived_phase3_per_model.csv>>

**Column definitions:**
- `pass_and_imports_oqs` = passes all tests and has an `import oqs` line. This is the Phase 3 definition, giving 84.
- `pass_and_strict_migrated` = calls `oqs.KeyEncapsulation`/`oqs.Signature` inside a function (`scripts/strict_migration.py`).
- `pass_and_imports_and_calls_oqs` = both (added in this dossier).
- `corrected` = removes the 5 A2 naming-bug false alarms.

**Key numbers:**

| Measure | Value |
|---|---|
| Frozen gate, all models | <<num p3_ALL_fail_frozen>> |
| Corrected, all models | <<num p3_ALL_fail_corrected>> |
| gpt-oss, frozen | <<num p3_openai_gpt-oss-120b_fail_frozen>> |
| gpt-oss, corrected | <<num p3_openai_gpt-oss-120b_fail_corrected>> |
| Strictest population (imports **and** calls liboqs), corrected | <<num p3_ALL_fail_imp_calls_corr>> |
| Baselines on the 84 | <<num p3_ALL_baselines>> |
| Passes all tests without importing liboqs (gate flags all of them with P2, per PROGRESS.md Session 9) | <<num p3_ALL_classical_pass>>: gemma <<num p3_gemma3_4b_classical_pass>>, qwen-3B <<num p3_qwen25-coder_3b_classical_pass>> |

**Inconsistency found while building this dossier:** <<num p3_strict_without_import>>.

### 8.4 Per-task breakdown (clustering)

<<table paper_dossier/tables/derived_phase3_per_task.csv>>

- (model, task) groups with ≥1 test-passing liboqs output: <<num p3_groups_total>>.
- Groups flagged: <<num p3_groups_flagged_frozen>> (frozen), <<num p3_groups_flagged_corrected>> (corrected).
- Distinct tasks flagged (corrected): <<num p3_tasks_flagged_corrected>>.
- The 5 samples of one task are correlated, so the effective sample size is closer to the group count than to the file count. **Cluster-aware statistics: NOT DONE.**

### 8.5 Ground truth

- **Who labelled:** an independent Claude subagent, blind to gate verdicts (allowed and forbidden files are listed in PROGRESS.md "Decision 2026-10-21").
- **Items:** <<num lab_items>>, sampled with seed 2026, at most 20 per model, from the 84 test-passing liboqs outputs.
- **Verdicts:** <<num lab_counts>>.
- **Not actually migrated:** <<num lab_unmigrated_items>>.
- **Human labels:** NOT DONE. **Second labeller / Cohen's kappa:** NOT DONE.

| Scope | Gate | Confusion | Precision | Recall | FPR | F1 |
|---|---|---|---|---|---|---|
| All 35 | frozen | <<num lab_all_frozen_confusion>> | <<num lab_all_frozen_precision>> | <<num lab_all_frozen_recall>> | <<num lab_all_frozen_fpr>> | <<num lab_all_frozen_f1>> |
| All 35 | corrected | <<num lab_all_corrected_confusion>> | <<num lab_all_corrected_precision>> | <<num lab_all_corrected_recall>> | <<num lab_all_corrected_fpr>> | <<num lab_all_corrected_f1>> |
| Real migrations (24) | frozen | <<num lab_real_frozen_confusion>> | <<num lab_real_frozen_precision>> | <<num lab_real_frozen_recall>> | <<num lab_real_frozen_fpr>> | <<num lab_real_frozen_f1>> |
| Real migrations (24) | corrected | <<num lab_real_corrected_confusion>> | <<num lab_real_corrected_precision>> | <<num lab_real_corrected_recall>> | <<num lab_real_corrected_fpr>> | <<num lab_real_corrected_f1>> |

**Disagreements:**
- item_30: missed F1, interprocedural flow.
- item_15 and item_31: missed F7, A5 coverage gap.
- item_18: false alarm, A2 naming bug.

Per-item data: `tables/original_results/gate_vs_labels_ai.csv`.

### 8.6 Repair

- **Items:** the 31 Phase 3 outputs that passed all tests, imported liboqs and failed the frozen gate. Each is repaired by its own model, with the same seed.
- **Fixed** = the final file passes all tests and the gate. **Denominators** are the items per row.

<<table paper_dossier/tables/derived_repair.csv>>

**Fixed by starting gate check:**

<<table paper_dossier/tables/derived_repair_by_check.csv>>

**Headline numbers:**
- Tests feedback: <<num rep_tests_ALL_fixed>> overall; gpt-oss <<num rep_tests_openai_gpt-oss-120b_fixed>>.
- Gate feedback: <<num rep_gate_ALL_fixed>> overall; gpt-oss <<num rep_gate_openai_gpt-oss-120b_fixed>>.
- 5 of the 20 gpt-oss gate items were A2 false alarms (task_20), so gpt-oss fixed 10 of 15 genuinely flagged items.
- **McNemar:** <<num rep_mcnemar>>.

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
| Total generation time (summed, not wall clock) | gemma <<num runtime_gen_gemma3:4b>>; qwen-3B <<num runtime_gen_qwen2.5-coder:3b>>; qwen-7B <<num runtime_gen_qwen2.5-coder:7b>>; gpt-oss <<num runtime_gen_openai/gpt-oss-120b>> |
| Groq tokens, Phase 3 | <<num groq_tokens_phase3>> |
| Groq tokens, Phase 4 | <<num groq_tokens_phase4>> |

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
| derived_benchmark_tasks | the 20 tasks | - | benchmark/*/meta.yaml, benchmark_validation.csv |
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
- **The gate was built and debugged on the same benchmark**, so in-sample detection is <<num val_gate_detect>>. The held-out result was <<num heldout_caught>>.
- **Gate bugs and gaps** (§7.6) change the counts. Phase 3 FAIL is <<num p3_ALL_fail_frozen>> frozen and <<num p3_ALL_fail_corrected>> corrected.
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
- **Clustering:** <<num p3_groups_flagged_corrected>> flagged (model, task) groups.

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
- **API usage:** Phase 3 Groq tokens <<num groq_tokens_phase3>>; Phase 4 UNVERIFIED (not logged). Cost: free tier.

## 14. Timeline, decisions and incidents (from PROGRESS.md)

| Date | Type | Event | Reason / handling |
|---|---|---|---|
| 10-12 | decision | API reference card added to the prompt, before any run | small models did not know the ML-KEM API |
| 10-12 | decision | migrate.py made resumable; timeouts and errors count as done | reproducibility |
| 10-12 | setup | liboqs from a prebuilt MSYS2 DLL | no CMake/MSVC to build liboqs |
| 10-13/14 | milestone | 20 tasks, 71 variants, 71/71 test-invisible | - |
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
| 10-20 | milestone | 400/400 scored; labelling set built | - |
| 10-21 | decision | user chose an independent AI labeller instead of human labelling | time |
| 10-21 | decision | repair design (2 conditions, ≤3 rounds) fixed before any repair output; "stop when unchanged" added after the pilot | identical prompt would repeat |
| 10-21 | fix | repair loop crashed on a non-Python reply | syntax check first |
| 10-21 | incident | internet outage ~10:40–11:46 | Groq runs stopped cleanly; relaunched |
| 10-22 | finding | A2 naming bug → 5 false alarms | corrected counts reported next to frozen ones |
| 10-23 | output | `docs/PROJECT_REPORT.md/.pdf` | - |
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
