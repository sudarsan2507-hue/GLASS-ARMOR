# PQ-GATE — Progress Log

**Current phase:** All experiments complete (Phases 0–4). Next: paper writing (deadline 13 Nov 2026). See "Phase 4 COMPLETE" at the end.
**Deadline:** 13 Nov 2026 (ICSE 2027 workshop)

---

## Decisions log (frozen before Phase 3)

- **2026-10-12, prompt API card (decided BEFORE any migration run).** No model output exists yet,
  so this choice was not influenced by results. The migration prompt is the fixed instruction plus an
  API reference card (`prompts.api_card` in `config.yaml`), identical for both models and all samples.
  - **Why:** in the smoke test, both small models misdescribed ML-KEM. Without API docs, almost no
    migration would run, leaving the "passes tests but insecure" rate with a tiny base.
    Real developers read docs, so giving the models the docs is fair.
  - **Content:** API usage only (ML-KEM-768, ML-DSA-65 incl. context-string variants, HKDF call
    syntax). It contains no security advice ("use a KDF", "use compare_digest", etc.).
    `scripts/check_api_card.py` checks that every line of the card runs.
  - **Threat to validity (report in paper):** the card *shows* the HKDF and ML-DSA context APIs, which
    may nudge models toward using them and so make F1/F7 flaws less likely than with no card.
    Our rates therefore describe "LLM + API docs", not "LLM alone".
  - Do not edit `prompts` in `config.yaml` once Phase 3 starts.
- **2026-10-12, resume support.** `harness/migrate.py` skips any sample whose `sample_<i>.json` log
  exists. The log is written after the `.py`, so a crash mid-sample redoes only that sample.
  Timeouts/errors are logged as `status: timeout/error` and count as done (not silently retried).
  **For Phase 3: keep the laptop plugged in and turn sleep off.**

---

## Session 1 — 2026-10-12

### Done
- **Machine:** Windows 10 Pro, Intel i5-6300U (2 cores / 4 threads), 15.9 GB RAM, **no dedicated GPU** (Intel HD 520), so Ollama runs on the CPU only.
- **Disk free:** C: 8.8 GB, D: 9.3 GB, E: ~28 GB before the model download.
- **Ollama 0.40.3** at `C:\Users\sudar\AppData\Local\Programs\Ollama\ollama.exe`, models in `E:\OllamaModels` (set by the `OLLAMA_MODELS` env var).
- Removed `llava:7b` (user approved in chat). Pulled `qwen2.5-coder:3b`. `ollama list` now shows:
  - `qwen2.5-coder:3b`, digest f72c60cabf62, 1.93 GB
  - `gemma3:4b`, digest c30276f7dffe, 3.35 GB
  - E: has 31.2 GB free afterwards.
- **Python env:** native Windows venv at `pq-gate\.venv` with Python 3.11. Python 3.14 is the default on this PC, but I used 3.11 for better wheel support. **WSL is not installed and was not needed.**
  - Everything installs from pip: cryptography, pytest, semgrep, bandit, pyyaml, requests, pandas, matplotlib, scipy, statsmodels, liboqs-python. Pinned versions are in `requirements.txt`.
  - **liboqs workaround:** liboqs-python tries to build the liboqs C library from source on first import, which needs CMake + MSVC. Those aren't installed (VS Build Tools 2022 is present, but without the C++ workload). Instead I used the prebuilt **liboqs 0.16.0** DLL from the MSYS2 package `mingw-w64-ucrt-x86_64-liboqs-0.16.0-1` (2.7 MB, no extra DLL dependencies), saved as `vendor/liboqs/bin/oqs.dll`. The venv file `.venv/Lib/site-packages/pqgate_oqs_path.pth` sets `OQS_INSTALL_PATH` automatically.
  - **If the venv is recreated, re-add that .pth line:**
    `import os; os.environ.setdefault('OQS_INSTALL_PATH', r'D:\Projects\Quantum_Encryption\pq-gate\vendor\liboqs')`
- `config.yaml` written: 2 models, temperature 0.2, num_ctx 8192, 5 samples with fixed seeds 1001–1005, 180 s timeout + 1 retry, fixed migration prompt, an empty commented-out slot for an API model.
- Folder skeleton created as in the brief.
- Smoke tests (scripts in `scripts/`):
  - `smoke_test_oqs.py`: **PASSED.** ML-KEM-768 shared secrets match (pk 1184 B, ct 1088 B, ss 32 B). ML-DSA-65 verifies, and a tampered message is rejected (pk 1952 B, sig 3309 B).
  - `smoke_test_ollama.py`: **PASSED**, both models reply over HTTP at localhost:11434.
    gemma3:4b: 36.8 s cold, 6.4 s warm. qwen2.5-coder:3b: 17.1 s cold.
    Both answers were factually **wrong**. gemma called ML-KEM "privacy-preserving machine learning", and qwen called it "machine learning-based key establishment". This is anecdotal only and not a result.

### Notes / risks
- CPU-only inference is slow. 200 migrations of 30–120-line files at ~3–8 tokens/s could take several hours per model, so plan to run them overnight.
- The network dropped briefly during pip installs (it recovered). Downloads may be flaky.

### Checkpoint 0: approved by the user (2026-10-12), with 3 additions, all done:
- README.md records the DLL source URL + SHA256 (`14EDAEBF…C015C9`).
- `harness/migrate.py` written early, with resume support (not yet run).
- API card added to the prompt (see Decisions log).

### Phase 1 so far: first 3 tasks built
| Task | Family | Classical → PQC | Variants |
|---|---|---|---|
| task_01_file_key_wrap | 1 | RSA-OAEP → ML-KEM-768 + HKDF + AES-GCM | F1, F3, F5, F6 |
| task_02_session_handshake | 2 | X25519 → hybrid X25519 + ML-KEM-768 | F2, F4, F10, F5 |
| task_03_document_signing | 3 | RSA-PSS → ML-DSA-65 (purpose in context) | F7, F7, F3, F5 |

- Variants are made from `reference_pqc.py` by exact text edits listed in each task's `variants.py`
  (`scripts/make_variants.py`). This keeps each one a minimal, auditable one-flaw diff. Re-run that script after editing a reference.
- Tests load the module under test from the `PQGATE_TARGET` env var (default `original.py`).
- `scripts/validate_benchmark.py`: **18/18 files pass all tests; 12/12 broken variants are test-invisible.**
  Output: `results/tables/benchmark_validation.csv`.
- Informal sanity check (scratchpad script, NOT a result): all 7 behavioural flaws (T1 F3, T2 F4/F10/F5,
  T3 F7×2/F5) really trigger on the variant and not on the reference.
- **Finding for Phase 2:** liboqs-python 0.16 signs with a too-short ML-DSA secret key without error
  (it only raises on too-long keys). A3 must use over-long keys to trigger error paths.
- Open design point: tests deliberately cover normal behaviour only (round trips, tamper, wrong key),
  not e.g. purpose-mismatch or nonce uniqueness. That is the paper's premise, but list it as a threat to validity.

- Checkpoint 1a approved by the user (2026-10-13): "do all of them then report".

---

## Session 2 — 2026-10-13 / 14

### Done: Phase 1 complete (20 tasks)
| Family | Tasks |
|---|---|
| 1 Key wrapping | 01 file_key_wrap, 04 backup_archive, 05 password_vault, 06 sealed_secrets |
| 2 Session setup | 02 session_handshake, 07 device_pairing, 08 tunnel_rekey, 09 sealed_messages |
| 3 Doc signing | 03 document_signing, 10 update_manifest, 11 invoice_signing, 12 audit_log |
| 4 Token signing | 13 api_token, 14 session_cookie, 15 license_key, 16 webhook_signature |
| 5 Config-chosen | 17 pke_provider, 18 signer_negotiation, 19 crypto_policy, 20 suite_negotiation |

- `scripts/validate_benchmark.py` (full run): **20 tasks, 71 broken variants, 71/71 test-invisible;
  all 20 originals and 20 references pass.** CSV: `results/tables/benchmark_validation.csv`.
- Originals are 55–107 lines (brief: 30–120).
- `scripts/benchmark_stats.py` writes `results/tables/benchmark_flaw_counts.csv`. Variants per flaw:
  F1 6, F2 5, F3 15, F4 3, F5 16, F6 5, F7 9, F8 3, F9 5, F10 4 (total 71).
  **Imbalanced:** F3/F5 are heavy and F4/F8 light. Recall per flaw for F4/F8 will rest on only 3 samples each.
- Informal sanity check (scratchpad scripts, NOT results): **33/33 behavioural flaws** (7 in tasks 01–03,
  26 in tasks 04–20) trigger on the variant and not on the reference. The other 38 variants are
  code-visible flaws (raw secret as key, `random`, `==`, key logging, missing transcript binding).
- Notes for Phase 2 (gate):
  - The F5 variants in task_04 (b2) and task_13 (b3) write key files to `%TEMP%` when run. The gate and
    evaluate.py should run targets with TEMP pointed at a throwaway dir.
  - A4 = monkeypatch `oqs.KeyEncapsulation.decap_secret` to return a wrong secret and check whether
    the session still succeeds (that is how F4 was confirmed).
  - A2 needs per-task knowledge of how to offer classical + PQC (config dict, suites list, header schemes).
    That will need a small per-task adapter (planned in meta.yaml or gate/adapters).
  - A3 on ML-DSA keys: use an over-long secret key (> 4032 B), because a short key does not raise.

### Pending
- CHECKPOINT 1b was accepted (user said "do phase 2").
- Decide whether to rebalance the flaw mix (F4×3, F8×3 are light) — deferred, gate first.

---

## Session 3 — 2026-10-14

### Done: Phase 2 complete, waiting at CHECKPOINT 2

#### Gate structure
- **Tier 1 static**
  - `gate/semgrep_rules/` (12 Semgrep rules; each rule's `metadata.check` gives its P-id):
    - P1 `p1_kem_output_must_go_through_kdf.yaml`: encap/decap output passed straight to AESGCM/ChaCha
    - P2 `p2_no_classical_crypto.yaml`: RSA / EC / OAEP imports and calls
    - P3 `p3_secrets_not_logged.yaml`: secret-named expression inside a log call, print, raise or file write
    - P4 `p4_no_random_for_crypto.yaml`: any use of the `random` module
    - P5 `p5_constant_time_compare.yaml`: mac/tag/check/csrf/digest compared with == or !=
  - `gate/static_dataflow.py` (small AST taint analysis, tags CL / PQ / CT):
    - P1: a raw CL/PQ secret reaches an AEAD key without `.derive()` (name-independent)
    - P6: hybrid modules only. Every KDF on a raw secret must take both secrets, and its info/salt must contain the KEM ciphertext
- **Tier 2 adversarial** (`gate/adversarial.py`). Probes are chosen by the functions a module exposes, so the same code runs on model outputs:
  - A1: liboqs set to None or made to raise → does keygen still work (silent fallback)?
  - A2: classical option offered alone or next to PQC. Covers X25519-only hello, RSA provider, ECDSA negotiation, x25519 policy, classical suites, and RS256 token / v1 webhook built with the task's original.py
  - A3: wrong / over-long keys and tampered ciphertext → does a probe key, or a long hex/escape run, appear in an exception, log record or stdout? Is tampered data accepted?
  - A4: `decap_secret` patched to return zeros → do both sides still agree?
  - A5: context, field or suffix changed after signing → does it still verify?
  - A6: the module's `AESGCM` wrapped to record (key, nonce) during a short workload → any pair repeated?
- **Runner** `gate/run_gate.py`: JSON verdict PASS / FAIL / ERROR.
  - ERROR means Semgrep failed. A crashed scan is never reported as PASS.
  - Targets are imported and run with TEMP / TMP / TMPDIR / tempfile pointed at a throwaway dir that is deleted afterwards. Checked: no key files left in the real %TEMP% after the final run.

#### Decision (logged before any model output exists)
- **2026-10-14:** P6, plus a second P1 detector, are implemented as an AST dataflow check instead of Semgrep.
  - **Why:** the property "the KDF input must contain BOTH secrets, and info must contain the ciphertext" is about something being *absent* along a data path. Semgrep patterns cannot express that.
  - The first, name/regex-based Semgrep P6 and P1 rules flagged 9 of the 20 correct references.
  - The dataflow version gives 0 false positives on references and needs no variable-name guessing.
  - **Still Tier 1 static** (no code is run). The paper should say "Semgrep rules + a small dataflow checker".

#### Gate validation: `scripts/validate_gate.py`, final run on 20 references + 71 variants
| | Tests only | Default Semgrep (p/python) | Bandit | PQ-GATE |
|---|---|---|---|---|
| Variants flagged (of 71) | 0 | 2 | 7 | **71** |
| Caught by an expected check | – | – | – | **71** |
| False positives (of 20 references) | 0 | 0 | 0 | **0** |

- Per flaw, PQ-GATE flags every variant of every flaw.
- The baselines catch only:
  - default Semgrep: F5 ×2 (logging calls)
  - Bandit: F6 ×5 (`random`) and F3 ×2 (a bad-practice import)
- Tables:
  - `results/tables/gate_validation.csv` (per file)
  - `gate_by_flaw.csv`
  - `gate_by_check.csv`
- Per check (TP / FN / fired on another variant / FP on references):

| Check | TP | FN | Fired on another variant | FP on refs |
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

- **Per-check misses (each variant is still caught by its other expected check):**
  - P2 misses task_19 b1/b2: classical X25519 kex. X25519 is legitimate inside hybrids, so P2 does not flag it; A2 catches both.
  - A1 misses task_01 b2: the RSA path only runs when a legacy PEM key is passed; P2 catches it.
- **"Fired on another variant" are real flaws, not noise:**
  - A3 sees keys logged at runtime (task_01/10/16 F5).
  - A1 sees F9 classical defaults that work without liboqs (task_17/18/19).
  - P6 sees task_08's classical-only peer.
- meta.yaml `expected_checks` were NOT changed after seeing results.

#### Threats to validity (must be stated in the paper)
- **In-sample result.** The rules and probes were written and debugged on this same benchmark: after early runs I fixed bugs and widened rules (A6, A3, P3 plural names, P1/P6 dataflow). So 71/71 and 0 FP are training-set numbers. They show the gate *can* express each flaw; they do not estimate its accuracy on unseen code.
  - **Proposal for Phase 3:** hand-label a random sample of model outputs that pass the tests (both models), blind to the gate verdict. Report gate precision / recall on that sample as the honest estimate.
- P3 and P5 rely on names (key/secret/…, mac/tag/check/…). Code with unusual names can evade them; A3 partly covers P3 at runtime.
- The dataflow checker is flow- and context-insensitive. For example, if two code paths share one KDF helper, a classical-only path can be hidden by the hybrid path (seen in task_19).
- A2/A5 probes know common API shapes (handshake, token, webhook, policy, suites). Model outputs that rename the public API get `None` (not applicable), never a guessed result.

#### Bugs found and fixed this session
- `python -m semgrep` is deprecated and exits 2 → call `semgrep.exe` directly.
- A cp1252 decode error on Semgrep output → decode the bytes as utf-8-sig.
- Semgrep `patterns:` with two `pattern:` entries means AND, so the old P4/P5 rules could never match → rewritten with `pattern-either`.
- `metavariable-regex` inside `pattern-either` is invalid → P3/P5 split into separate pattern blocks.
- The old A6 compared nonces across two channels and missed per-channel nonce reuse → replaced by the (key, nonce) recorder.
- The old A3 never passed the probe keys to the leak detector, so `repr(key)` leaks went unseen → fixed.
- Leftover key files in %TEMP% came from an early, stopped run with the old code; deleted.

### Pending
- **CHECKPOINT 2 review by the user.**
- Still open from before: rebalance the flaw mix (F4 ×3, F8 ×3)? Adding variants now would be out-of-sample for the gate, which is useful.

### Next step (after approval)
**Phase 3:** run `harness/migrate.py` (2 models × 20 tasks × 5 samples = 200 migrations; CPU-only, plan overnight). Then run the tests and the gate on every output.

### How to run things
```
cd D:\Projects\Quantum_Encryption\pq-gate
.\.venv\Scripts\python.exe scripts\smoke_test_oqs.py
.\.venv\Scripts\python.exe scripts\smoke_test_ollama.py
.\.venv\Scripts\python.exe scripts\make_variants.py          # rebuild broken/ from variants.py
.\.venv\Scripts\python.exe scripts\validate_benchmark.py     # all tests on all files (~5 min)
.\.venv\Scripts\python.exe scripts\benchmark_stats.py        # flaw counts
.\.venv\Scripts\python.exe scripts\validate_gate.py          # gate + baselines on benchmark (~10 min)
.\.venv\Scripts\python.exe gate\run_gate.py <file.py> [--task task_xx] [--json]
.\.venv\Scripts\python.exe gate\static_dataflow.py <file.py> # dataflow checks only
```

---

## Session 4 — 2026-10-14 (user: "do all of these" → held-out variants, Phase 3, blind labelling)

### 1. Held-out F4/F8 variants: an out-of-sample test of the gate
- **Protocol:**
  1. Gate frozen first: `results/frozen/gate_freeze_2026-10-14.sha256` holds hashes of all gate files.
  2. Then 6 new variants were written from the brief's flaw definitions, in shapes not used anywhere else. Their `expected_checks` went into meta.yaml (marked `held_out: true`) before any gate run.
  3. All 6 were checked test-invisible: every functional test passes.
  4. Hashes were re-checked (unchanged), then the gate was run **once**.
- **Result: `results/tables/gate_heldout_2026-10-14.json`: 4 of 6 caught.**

| Variant | Flaw | Expected | Gate flags | |
|---|---|---|---|---|
| task_02 b5 KEM ciphertext used as the PQ secret | F4 | P6, A4 | A4, P6 | caught |
| task_08 b5 "PQ secret" = sha256(public KEM key) | F4 | P6, A4 | A4, P6 | caught |
| task_20 b5 typo `classical + classical` | F4 | P6, A4 | P6 | caught (A4 cannot drive the suites API) |
| task_05 b5 check value compared as hex string `!=` | F8 | P5 | P5 | caught |
| task_07 b5 `tag_a.hex() == tag_b.hex()` | F8 | P5 | – | **missed** |
| task_14 b4 hand-written early-exit byte loop | F8 | P5 | – | **missed** |

- **Reading:** the dataflow P6 and A4 generalise to new F4 shapes. The name-based P5 does not generalise (1/3).
  - This is the paper's first honest out-of-sample number. **Not tuned afterwards.**
  - Any later P5 improvement must be judged on new data (the hand labels), not on these 6.
- The benchmark now has 77 variants: F4 = 6, F8 = 6. The Session 3 in-sample gate table refers to the original 71.
  - Re-running `validate_gate.py` now would mix in the 6 held-out variants; filter on `held_out` when reporting.

### 2. Phase 3 started (2026-10-14)
- **Decision before the run, harness settings only; the prompt and API card are unchanged:**
  - `timeout_s` 180 → 900, and a new `num_predict: 3072` cap. Both are logged in every sample JSON (`timeout_s`, `num_predict`, `done_reason`).
  - **Why:** a throwaway timing probe (scratchpad, not a result) took 269 s (gemma) and 223 s (qwen) for one mid-size task: about 1,000 prompt tokens and about 900 output tokens at ~5 tok/s, CPU only. With 180 s, almost every sample would have been logged as a timeout.
- Phase 3 inputs frozen: `results/frozen/phase3_inputs_2026-10-14.sha256` (config, harness, 20 originals).
- **Running:** `harness/migrate.py`, log in `results/logs/phase3_migrate.log`.
  - About 4–6 min per sample → **roughly 14–20 h for 200**.
  - Resumable: if the laptop sleeps or restarts, just run the same command again.
  - **Keep it plugged in, sleep off, and avoid other heavy work** (the CPU is saturated; even small commands slow down).
- **First sample** (gemma3:4b, task_01, s0): status ok. It pasted the API card verbatim at module level without `import oqs`, so the tests fail. This is real model output (one fenced block, checked).

### 3. Scoring pipeline (written; tried on that 1 sample, works end to end)
- **`scripts/evaluate.py`** writes `results/tables/phase3_eval.csv`. Per sample it records:
  - generation status
  - token cap hit
  - syntax OK
  - uses liboqs
  - tests passed / failed
  - gate verdict and flags (static batch + adversarial)
  - default-Semgrep and Bandit counts
- **Model outputs are untrusted code.**
  - Tests and adversarial checks run in subprocesses with a 300 s timeout, using a throwaway cwd and TEMP.
  - The adversarial worker is `scripts/adversarial_worker.py`; it reuses the frozen gate code unchanged.
- **Headline metric:** of the outputs that use liboqs AND pass all tests, the share the gate fails.
  - Outputs without liboqs are "not migrated" and reported separately; they would trivially pass the tests.

### 4. Blind labelling (after evaluate.py has run on all 200)
- `scripts/make_label_sample.py` samples up to 20 outputs per model, from those that use liboqs and pass all tests (fixed seed 2026). It writes:
  - `labeling/items/item_NN.py` (neutral names)
  - `labeling/labels.csv` (to fill in: secure yes/no/unsure, F1–F10, notes)
  - `labeling/GUIDE.md` (the brief's exact F1–F10 table plus rules)
  - `results/labeling_key.csv` (item → model; do not open while labelling)
- It refuses to overwrite `labels.csv`.
- **Who labels:** the user, ideally. I built the gate and the variants, so I am not a blind labeller.
  - Optional: I label separately afterwards, and we report agreement (Cohen's kappa) as a check.
- **Then:** gate precision/recall vs the labels = the honest accuracy estimate for the paper.

### Pending
- Wait for the migrations to finish (check `results/logs/phase3_migrate.log`).
- Then:
  1. `python scripts/evaluate.py` (~1 h, run when the migrations are done)
  2. `python scripts/make_label_sample.py`
  3. The user labels the items
  4. Compute gate-vs-label agreement (script still to write)
  5. CHECKPOINT 3
- Repair-loop comparison (gate feedback vs test feedback) comes after that.

### How to run things (Phase 3)
```
.\.venv\Scripts\python.exe harness\migrate.py              # resume / continue migrations
.\.venv\Scripts\python.exe scripts\evaluate.py             # score all outputs (after migrations)
.\.venv\Scripts\python.exe scripts\make_label_sample.py    # build the blind labelling set
```

---

## Session 5 — 2026-10-15

- The migration run stopped at 02:08 when the session ended / laptop slept, with 52/200 done (all gemma3:4b, all `ok`, 0 timeouts). It was **resumed** at 16:30 (same command; resume skips finished samples).
- **Bug fixed in `scripts/evaluate.py`:** `PQGATE_TARGET` is now resolved to an absolute path, because tests run in a throwaway cwd. A relative path made every test "fail" in a preview script. evaluate.py itself already passed absolute paths, so no stored result was affected.
- **Preview, NOT a final result** (tests + liboqs use only; no gate; gemma3:4b, 53 outputs):
  - 51 parse
  - **40 pass all tests**
  - **6 use liboqs at all**
  - **3 pass tests AND use liboqs** (all task_03)
  - Most gemma outputs return the classical code almost unchanged. They "pass the tests" because the tests come from the classical original.
- **Implications:**
  1. **Yield risk confirmed for gemma.** The headline population ("migrated, passes tests") will be tiny unless qwen does much better. Wait for the qwen numbers, then decide whether a stronger model is needed (user decision; options below).
  2. **New secondary finding:** the existing tests cannot tell whether a migration happened at all. An unmigrated classical file passes them. The gate flags these (P2).
- **Options for a stronger model** (needs the user's OK; not done):
  - (a) local `qwen2.5-coder:7b` (~4.7 GB on E:, ~2x slower on CPU)
  - (b) a free-tier API model via the commented slot in config.yaml (fast; needs an API key)
- **Decision 2026-10-15 (user: "do it"):** added a third local model, `qwen2.5-coder:7b`, to `config.yaml`.
  - **Why:** the gemma preview showed only 6/53 outputs even attempt a liboqs migration, so the headline population would be too small.
  - **Chosen on yield grounds only.** The decision came after a tests/liboqs preview; no gate verdict had been computed on any model output. The prompt, API card and generation settings are unchanged.
  - New input hashes: `results/frozen/phase3_inputs_2026-10-15_added_7b.sha256` (only config.yaml differs from the 10-14 file).
  - Download log: `results/logs/pull_qwen7b.log`.
  - Run order: the current run (gemma3:4b + qwen2.5-coder:3b) finishes first; then the same `harness\migrate.py` command runs the 7B's 100 samples (~2x slower on CPU, so roughly 15 h more).
- **2026-10-15 21:20:** both background jobs had died when the Claude Code session ended. State at that point:
  - migrations at 95/300 (gemma 95/100, all ok)
  - the 7B download at ~11%
- Both were restarted as **detached Windows processes** (`Start-Process cmd /c ... >> log`), so they survive session ends.
- **If they stop again** (reboot or sleep), re-run either command; both resume:
  - `ollama pull qwen2.5-coder:7b`
  - `.venv\Scripts\python.exe harness\migrate.py`
- Watch progress in `results/logs/phase3_migrate.log` and `results/logs/pull_qwen7b.log`.

---

## Session 6 — 2026-10-18

- Found everything stopped since **2026-10-15 22:04** (laptop off/asleep), at 106/300:
  - gemma3:4b 100/100
  - qwen2.5-coder:3b 6/100
  - the 7B download unfinished
- On restart (14:46), **Ollama auto-updated itself 0.40.3 → 0.40.6**. The installer stopped the Ollama server and killed both jobs.
- **Reproducibility handling (decided before any gate run on qwen outputs):**
  - **gemma3:4b:** all 100 samples were generated under Ollama 0.40.3 (version recorded in Session 1; all its samples predate the update). Kept as they are.
  - **qwen2.5-coder:3b:** the 6 samples made under 0.40.3 were **moved, not deleted**, to `results/raw_superseded/qwen2.5-coder_3b_ollama-0.40.3/`. They are being regenerated under 0.40.6 with the same seeds, so each model runs under exactly one Ollama version.
  - **qwen2.5-coder:3b and :7b** therefore both run under 0.40.6.
  - Model digests are unchanged after the update (qwen2.5-coder:3b f72c60cabf62, gemma3:4b c30276f7dffe), so the weights are identical; only the inference engine version differs.
  - **Report in the paper:** gemma 0.40.3 vs qwen 0.40.6.
- `harness/migrate.py` now records `ollama_version` in every sample JSON (logging only). New input hashes: `results/frozen/phase3_inputs_2026-10-18_ollama-0.40.6.sha256`.
- **Restarted (detached):**
  - migrations, from qwen2.5-coder:3b task_01 s0 (194 to go: ~6 h for 3B, ~13–15 h for 7B)
  - the 7B download (started over, ~1.5 h)
- **To avoid repeats:**
  - Keep the laptop on and plugged in. Sleep on AC is already "never", so the Oct 15 stop was probably a shutdown or the lid being closed.
  - If the Ollama app's settings offer disabling automatic updates, turn that off until Phase 3 is done.
- **16:40:** 132/300 (qwen2.5-coder:3b 32/100), running fine; the 7B download is at 30% and slow.
  - Added `scripts/keep_migrating.ps1`, a detached watchdog. Whenever no migrate.py is running it relaunches it (resume), waiting for qwen2.5-coder:7b to be installed if needed, and stops at 300.
  - It does not survive a reboot. After a reboot, start it again with:
    `Start-Process powershell -WindowStyle Hidden -ArgumentList '-File','scripts\keep_migrating.ps1'`

- **2026-10-18 evening:** the laptop was **unplugged at 17:22** and **shut down unexpectedly at 18:12** (battery; Windows event 6008). It rebooted at 18:31, but the watchdog does not survive reboots, so nothing ran until 22:50.
  - **Two qwen2.5-coder:3b samples got HTTP 500 from Ollama** around the crash (task_10 s4, task_15 s1).
  - **Rule (applies from now on):** infrastructure failures (Ollama server errors, machine crash) are re-run. Model-level outcomes (timeouts, bad or non-working code) are never re-run.
  - The two error samples were moved (kept) to `results/raw_superseded/qwen2.5-coder_3b_infra_errors/` and are being regenerated with the same seeds.
- **22:50:** download and watchdog restarted; the watchdog relaunched migrate.py at 170/300.

---

## Session 7 — 2026-10-19

- **gemma3:4b 100/100 and qwen2.5-coder:3b 100/100 finished at 00:25** (200/300). The two re-run infrastructure-error samples completed ok.
- **The 7B download failed at its final step:** `remove ...-partial-0: The system cannot find the file specified`. This is Ollama tripping over chunk files left by the earlier interrupted pulls; a retry gave the same error.
  - So the run sat idle from 00:25 to 21:05; the watchdog was waiting for the model.
  - **Fix:** deleted only the 7 `sha256-60e05f21…-partial*` files (the broken half-download), then started a clean pull (log `results/logs/pull_qwen7b_clean.log`, ~1.5 h at ~0.8 MB/s).
  - The watchdog (still running) starts the 7B's 100 samples once the model is installed: ~13–15 h on CPU.
- **Next, once at 300/300:**
  1. `scripts/evaluate.py`
  2. `scripts/make_label_sample.py`
  3. CHECKPOINT 3
- **Yield preview (tests + liboqs use only, no gate; NOT the final numbers):**
  - gemma3:4b: 71/100 pass tests, 11 use liboqs, **5 both**
  - qwen2.5-coder:3b: 52/100 pass tests, 12 use liboqs, **1 both**
  - So the headline population has only 6 of 200. Most test-passing outputs are unmigrated classical code.
- **Decision 2026-10-19, logged before any of its outputs exist:** add a large-model condition through the Groq API, **`openai/gpt-oss-120b`**.
  - **Why this model:** the strongest model on the user's Groq key, open weights (reproducible), widely used.
  - **Same everything:** the same prompt, API card, temperature 0.2 and seeds 1001–1005.
  - `max_completion_tokens` is 8192 because it counts the model's reasoning tokens too.
  - **Logged per sample:** API model id, `system_fingerprint`, token usage, finish reason, and the model's reasoning text.
  - **Retries:** rate-limit (429) and server (5xx) replies are waited out and retried as infrastructure. Other failures are logged as `error`.
- **The key** lives in `pq-gate/.env` (`GROQ_API_KEY=`). `.env` is git-ignored, and the key is never printed or logged.
- **Code changes:**
  - `harness/migrate.py`: added the Groq provider. Folder names now also replace `/` (Groq output goes to `results/raw/openai_gpt-oss-120b/`).
  - evaluate.py / make_label_sample.py: adjusted for the Groq log format and folder names.
  - Watchdog: target is now 400, and it runs only the 3 local models.
- New input hashes: `results/frozen/phase3_inputs_2026-10-19_groq.sha256`.
- **22:50, Groq status:** 44 ok samples kept.
  - Groq's free tier started asking for 8–17 min waits, i.e. a rate/daily cap.
  - Two samples failed on dropped connections (`RemoteDisconnected`). They are infrastructure failures, so they were moved to `results/raw_superseded/openai_gpt-oss-120b_infra_errors/` and will be redone.
  - **The Groq client was hardened:**
    - network drops are retried
    - a rate-limit wait over 300 s raises `StopRun`: the run stops and **writes no sample**
    - only definite API rejections (other 4xx) are recorded as `error`
- **The 7B download failed again** (`unexpected EOF`, flaky network).
- **The watchdog now handles everything:**
  - retries the pull
  - runs the local models
  - relaunches the Groq run every 30 min until its 100 samples exist
- Fixed a cmd quoting bug in the watchdog's pull command (a command starting with a quoted path was mangled).
- **State at 22:55:**
  - gemma 100, qwen-3B 100, gpt-oss-120b 44/100 (waiting out the cap)
  - 7B download at 39% (~45 min), then ~14 h of local generation

---

## Session 8 — 2026-10-20: first Phase 3 scores (377/400 samples; Groq still 77/100)

- **Local runs complete:** gemma3:4b, qwen2.5-coder:3b and qwen2.5-coder:7b, 300/300, all `ok`. The 7B took ~4 min/sample.
- `scripts/evaluate.py` now runs Semgrep/Bandit in chunks of 50 files (the Windows command-line length limit broke the first attempt).
  - Log: `results/logs/evaluate_run1.log`; table: `results/tables/phase3_eval.csv`.
- **First-pass results.** These are GATE VERDICTS, not confirmed flaws; confirmation comes from the blind labels:

| Model | Parse | Pass all tests | …and use liboqs | …and gate FAIL |
|---|---|---|---|---|
| gemma3:4b | 98/100 | 71 | 5 | 5 (P2 ×5, A1 ×2, P3 ×2) |
| qwen2.5-coder:3b | 95/100 | 52 | 1 | 1 (P2, A2) |
| qwen2.5-coder:7b | 100/100 | 9 | 9 | 5 (P2 + A1 ×5) |
| gpt-oss-120b (77 so far) | 75/77 | 50 | 50 | 10 (P1 ×5, A5 ×5) |

- **Baselines** on the 65 test-passing liboqs migrations: default Semgrep flagged **0**, Bandit flagged **0**.
- **Observations:**
  - The small models mostly keep the classical code. 66 (gemma) and 51 (qwen-3B) outputs pass the tests while not using liboqs at all: the tests cannot tell whether a migration happened.
  - The 7B attempts real migrations far more often, so it breaks the tests more often (9/100 pass).
  - **Flags cluster by task** (the 5 seeds of one task give similar code):
    - gpt-oss: P1 in task_04/06 (raw KEM secret used as the AES key); A5 in all 5 task_13 samples (token signature without the context string)
    - qwen-7B: task_05/06 (A1 + P2: RSA fallback still reachable)
    - gemma: task_03/12
  - **The effective sample size is the number of distinct tasks, not samples.** Report per task as well, and use cluster-aware statistics.
- **Next:**
  1. When Groq reaches 100: re-run evaluate.py
  2. make_label_sample.py
  3. The user labels blind
  4. Gate-vs-label agreement
  5. CHECKPOINT 3
- **2026-10-20 12:05:** the laptop rebooted at 11:51 and the watchdog died. Before that, Groq had failed at 10:26 on `ConnectionError` ×10 (internet outage), stopping cleanly with no sample written. Watchdog restarted; Groq resumed at 80/100.
- **13:50:** watchdog bug fixed. Its "is Groq running?" check matched any process mentioning gpt-oss, including my wait-until-100 helper, so it stopped relaunching Groq after 12:36. It now matches only `migrate.py --models openai/gpt-oss`. Groq at 91/100. A queued helper runs the final evaluate.py + make_label_sample.py once Groq reaches 100.

---

## Session 9 — 2026-10-20: Phase 3 complete (400/400) — final gate scores; labelling set built

- All 400 migrations finished (Groq done at 18:22). Final scoring: `results/logs/evaluate_final.log`, `results/tables/phase3_eval.csv`.
- **Final results.** GATE VERDICTS; not yet confirmed by labels:

| Model | Pass all tests | …and use liboqs | …and gate FAIL | Checks fired |
|---|---|---|---|---|
| gemma3:4b | 71 | 5 | 5 | P2 5, A1 2, P3 2 |
| qwen2.5-coder:3b | 52 | 1 | 1 | P2, A2 |
| qwen2.5-coder:7b | 9 | 9 | 5 | P2 5, A1 5 |
| gpt-oss-120b | 69 | 69 | **20 (29%)** | P1 9, A2 7, A5 5, P2 2, P3 1 |
| **all** | 201 | **84** | **31 (37%)** | |

- **Headline population:** 84 test-passing liboqs migrations.
  - The gate fails 31, spread over **9 distinct tasks** (of the 18 tasks represented).
  - Baselines on the same 84: default Semgrep 0, Bandit 1.
- **Secondary finding:** 117 outputs pass all tests without using liboqs at all (not migrated); the gate flags all 117 (P2).
- **Blind labelling set built** (`scripts/make_label_sample.py`, seed 2026): 35 items from the 84, at most 20 per model.
  - By model: gpt-oss 20, qwen-7B 9, gemma 5, qwen-3B 1.
  - Files: `labeling/items/item_NN.py`, `labeling/labels.csv`, `labeling/GUIDE.md`. Key in `results/labeling_key.csv` (do not open while labelling).
- **Next:**
  1. The user labels the 35 items blind
  2. I write the gate-vs-label agreement script (precision / recall per check, with clustering by task)
  3. CHECKPOINT 3
- Housekeeping: the watchdog stopped by itself at 400.
- Added `scripts/compare_labels.py` (gate vs blind labels: per item and per (model, task) group; precision, recall, per-flaw hits, misses, false alarms; writes `results/tables/gate_vs_labels.csv`). Run it only after all 35 are labelled, because it reveals gate verdicts. Labels at the time of writing: 0/35.

---

## Session 10 — 2026-10-21: Phase 4 (repair loop) — design fixed before any repair output

- **Question:** does gate feedback fix test-passing insecure migrations where test feedback does not?
- **Items:** the 31 Phase 3 outputs that pass all tests, use liboqs and FAIL the gate (gpt-oss 20, gemma 5, qwen-7B 5, qwen-3B 1). Each is repaired by the model that wrote it, with the same seed and temperature.
- **Conditions:**
  - `tests`: feedback = test-suite results only ("all N tests passed", or the failing tests)
  - `gate`: the same, plus the gate's findings. Static findings use the rule messages; adversarial findings get a plain-language sentence.
  - The prompts are in `config.yaml` → `repair.prompt_tests` / `repair.prompt_gate`, identical except for the feedback. The API card is appended to both.
- **Rounds:** minimum 1, maximum 3. Stop once the condition's own signal is clean (tests: tests pass; gate: tests pass and gate PASS).
  - Every round is saved under `results/repair/<cond>/<model>/<task>/sample_<i>/round_k.py/.json`.
  - Groq rate limits stop the run without writing anything; re-run resumes.
- **Outcome measure:** tests + gate on each round's file. The gate is frozen (hashes re-checked OK before Phase 4).
- **Known circularity:** in the `gate` condition the gate is both the feedback and the judge, and P3/P5 are name-based, so a model can "fix" a finding by renaming.
  - **Mitigation:** hand-audit every gate-condition item the gate counts as fixed, and report "real fix" vs "evaded the check". If possible, the user labels a sample of repaired files blind too.
- Code: `harness/repair.py`. Input hashes: `results/frozen/phase4_inputs_2026-10-21.sha256`.
- **Pilot item** (qwen2.5-coder:3b task_20 s3, gate condition): given 3 gate findings (P2 ×2, A2), the model returned the file **unchanged** in all 3 rounds.
- **Design addition after the pilot, before the full run:** also stop when the model returns the file unchanged. The next prompt would be byte-identical with the same seed, so Ollama would repeat itself. For Groq, determinism is best-effort only, so this is a small approximation; it is noted.
  - The pilot item keeps its 3 identical rounds; the outcome is the same either way.
- Tests/adversarial subprocesses set `PYTHONDONTWRITEBYTECODE=1` (no `__pycache__` next to outputs). Hashes refreshed.
- **Full run:** detached watchdog `scripts/keep_repairing.ps1`.
  - Local models run straight through; Groq is relaunched every 30 min through rate limits.
  - Logs: `results/logs/phase4_local.log`, `results/logs/phase4_groq.log`.
- **After a reboot, restart it with:**
  `Start-Process powershell -WindowStyle Hidden -ArgumentList '-File','scripts\keep_repairing.ps1'`
- **01:35 fix:** the local repair run crashed when qwen-3B answered in prose instead of code (Semgrep refused the file and the StaticError propagated). `evaluate()` in repair.py now checks syntax first (verdict `NOT VALID PYTHON`, tests counted as failing) and records any other static-tier failure as `ERROR` instead of crashing. Hashes refreshed. The watchdog resumes the run.
- **Decision 2026-10-21 (user chose: "Independent AI agent"):** the 35 items are labelled by a fresh Claude subagent instead of the user.
  - **Blinding:** it may read only `labeling/GUIDE.md`, the items, the empty `labels.csv` template and each task's original/reference/test files. It is explicitly barred from `results/`, `gate/`, `scripts/`, `harness/`, PROGRESS.md, README.md, config.yaml, and the benchmark's `broken/`/meta/variants.
  - **Output:** `labeling/labels_ai.csv`. `labeling/labels.csv` stays empty for an optional human pass.
  - **The paper must report** these as AI labels (weaker than human ground truth). A human spot-check of ~10 items is recommended.
  - `scripts/compare_labels.py` now takes the labels file as an argument and writes `results/tables/gate_vs_<labels file>.csv`.

---

## CHECKPOINT 3 — 2026-10-21: gate vs blind (AI) labels

- **Labeller:** independent Claude subagent, blind to gate verdicts. 35 items: 16 secure, 19 insecure, 0 unsure.
  - Flaws: F1 ×6, F7 ×2, F5 ×2 (demo `main()` prints), F3 ×1.
  - **11 items "not actually migrated":** oqs imported but unused, crypto still RSA/ECDSA. One renames classical suites to "ML-KEM-768".
  - Labels: `labeling/labels_ai.csv`; comparison: `results/tables/gate_vs_labels_ai.csv`.
- **Gate vs labels, all 35 items:**
  - per item: precision **16/17 = 94%**, recall **16/19 = 84%**
  - per (model, task) group: precision 7/8 = 88%, recall 7/9 = 78%
- **Disagreement analysis** (gate NOT changed; these are limitations to report):

| Item | Type | Cause |
|---|---|---|
| item_30, F1 | FN | the raw ML-KEM secret leaves the module (returned by `unlock()`) and comes back as an argument to `add_entry()`; the dataflow check does not follow values through the caller |
| item_15/31, F7 (task_18) | FN | A5 has no probe for the `seal_envelope`/`open_envelope` API (coverage gap) |
| item_18 | FP | **gate bug:** the A2 suite probe treats a suite as PQ only if its name contains "MLKEM"; the model named it "ML-KEM-768" |

- **Important re-reading:** all 11 "not migrated" items (gemma ×5, qwen-3B ×1, qwen-7B ×5) are flagged by the gate (P2); these are easy cases.
  - **On the 24 real migrations:** 8 insecure, and the gate catches **5/8 = 63%**. Precision there is 5/6.
  - **Report 63% (real flaws) as the honest recall, not 84%.**
- **Migration definition:** `import oqs` over-counts (11/35 in the sample are not real migrations).
  - `scripts/strict_migration.py` (oqs called inside a function) agrees with the labeller on 33/35; it is fooled only by demo `main()` code (items 20, 25).
  - Under it: 83 test-passing migrations, gate FAIL 30 (36%). gpt-oss 69 → 20; gemma 10 → 10; qwen-7B 4 → 0; qwen-3B 0.
  - Table: `results/tables/phase3_eval_strict.csv`.
- **Caveat for the paper:** the labels are AI-generated (blind, independent agent), not human. A human spot-check of ~10 items is still recommended.
- **Phase 4: local models finished (2026-10-21).** Tables: `results/tables/repair_summary.csv`, `repair_items.csv`.
  - **gate condition:** 0/11 fixed.
    - gemma: 0/5 (changed code, flags remain)
    - qwen-3B: 0/1 (never changed)
    - **qwen-7B: 0/5, broke the tests in all 5**
  - **tests condition:** 0/11 fixed (gemma 0/5, qwen-3B 0/1, qwen-7B 0/5; 3 of qwen-7B never changed, 1 broke tests).
  - **Reading:** for the small local models, specific security feedback does not lead to a working fix. The 7B tries and breaks the code instead.
  - **Pending:** Groq gpt-oss — tests condition 17/20, gate condition 0/20 (rate-limited, auto-resumes).
- **2026-10-21 08:00, Groq repair:**
  - **tests condition finished:** gpt-oss-120b **0/20 fixed** (1 broke tests).
  - **gate condition:** 6/20 done; **5 fixed**, 1 broke tests.
  - **Hand audit of the 5 fixes:** all are P1 items (task_04 s3, task_06 s0/s1/s3/s4). Each added an HKDF-SHA256 derivation of the AES key from the KEM shared secret: a **real fix, not an evaded check**. The name-independent dataflow P1 confirms the raw secret no longer reaches AESGCM. **Audit result: 5/5 genuine.**
  - The remaining 14 gate-condition items resume automatically (rate limit).
- **2026-10-21 08:00–11:50:** no Groq progress. From ~10:40 every attempt failed with ConnectionError (network outage); the runs stopped cleanly, writing nothing. At 11:50 the internet was back and the exact failing request (task_13 s1) succeeded in a manual replay (reply discarded, not used as data). The Groq repair was relaunched by hand and is progressing (task_13 s1–s2).

---

## Phase 4 COMPLETE — 2026-10-22 (Groq part finished 00:42)

**Fixed = final file passes all tests AND the gate passes** (`results/tables/repair_summary.csv`, `repair_items.csv`):

| Model | tests-only feedback | gate feedback |
|---|---|---|
| gpt-oss-120b (20 items) | **0/20** fixed (1 broke tests) | **10/20** fixed (4 broke tests) |
| gemma3:4b (5) | 0/5 | 0/5 |
| qwen2.5-coder:7b (5) | 0/5 (1 broke tests, 3 never changed) | 0/5 (**5 broke tests**) |
| qwen2.5-coder:3b (1) | 0/1 (never changed) | 0/1 (never changed) |
| **all 31** | **0/31** | **10/31** |

- **Hand audit of all 10 gate-condition fixes: all genuine.**
  - 9 added an HKDF derivation of the AES key (P1): task_04 s3, task_06 s0/s1/s3/s4, task_17 s0/s1/s2/s4.
  - task_17 s1 also removed the RSA provider (P2/A2).
  - task_19 s2 removed the classical x25519 key-exchange option (A2/P2).
  - None evaded a check by renaming.
- **New gate false positive found in the audit:** P3 flagged `raise ValueError(f"... {len(shared_secret)} ...")`. Only the length leaks, not the secret; the name-based rule matched `shared_secret` inside `len()`. Add to the limitations list (with the A2 "ML-KEM-768" naming bug and the A5 coverage gap).
- **Reading:**
  - Tests give no repair signal ("all tests passed"): 0/31 fixed.
  - Gate findings let the strongest model fix half its flawed migrations, all genuinely.
  - The small models cannot act on the feedback; qwen-7B breaks working code when it tries.
  - **Not fixed by gpt-oss:** the A5 signature-context items (task_13). See repair_items.csv for each item's final flags.
- **Status:** all experiments done (Phases 0–4).
  - **Remaining:** write the paper (deadline 13 Nov 2026).
  - **Optional but recommended:** a human spot-check of ~10 AI labels (`labeling/labels_ai.csv`).
- **Error analysis after Phase 4 (2026-10-22): the A2 naming bug also produced 5 Phase 3 false alarms.**
  - All 5 gpt-oss task_20 outputs (s0–s4) name their suite `ML-KEM-768-AES256GCM`. A2's suite probe counts a suite as post-quantum only if its name contains "MLKEM", so it flagged them.
  - For all 5, A2 is the only gate flag. The blind labeller rated the sampled one (item_18) secure.
  - So these were never flawed, which is why gate feedback could not "fix" them.
  - **The gate code is NOT changed** (it stays frozen); corrected numbers are reported alongside the frozen ones:
    - Phase 3 test-passing liboqs migrations, gate FAIL: frozen **31/84** → corrected **26/84**. gpt-oss: 20/69 → **15/69**.
    - Phase 4 gpt-oss gate condition: **10/20** fixed (frozen) = **10/15** of the genuinely flagged items.
    - The remaining unfixed items are task_13 ×5 (A5 signature context): 1 kept the flag, 4 broke the tests.
  - **Paper:** describe the bug, give both counts, and list it with the other gate limitations. They are: the A5 coverage gap (task_18), the cross-function dataflow miss (item_30), the P3 `len(secret)` false positive, and the name-based P3/P5.
- **2026-10-23:** end-to-end report written: `docs/PROJECT_REPORT.md` and `docs/PROJECT_REPORT.pdf` (why/how/when, all results, limitations, full code map).
- **2026-10-31:** paper dossier built: `paper_dossier/` (DOSSIER.md, numbers.csv with 97 sourced numbers, derived tables with .tex, code examples) and `paper_dossier.zip` (80 KB). Analysis only (`scripts/dossier/compute_stats.py`, `build_dossier.py`): Wilson CIs, exact McNemar (p = 0.0020), per-task clustering, runtimes, Groq tokens. **New finding:** 8 gemma test-passing outputs call liboqs in functions without importing it. Added the stricter 'imports AND calls' measure: 75 real migrations, 17 corrected gate FAIL (22.7%). Plain summary for the mentor: `docs/project_summary_simple.csv`.
