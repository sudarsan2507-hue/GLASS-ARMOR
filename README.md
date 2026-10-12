# PQ-GATE

Research artifact for *"Passing Tests, Failing Security: Measuring and Gating LLM-Driven
Post-Quantum Migrations"*.

- `benchmark/`: small Python crypto programs, each with a correct PQC migration and insecure, test-passing variants
- `gate/`: security gate (Semgrep rules + adversarial checks)
- `harness/`: runs local LLMs (Ollama) to migrate code, then evaluates the outputs
- `results/`: raw model outputs, CSV tables and figures
- `config.yaml`: every experiment setting (models, temperature, seeds, prompts)

## Setup (Windows, native, no WSL)

Tested on Windows 10 Pro, Python 3.11, Ollama 0.40.3, CPU only.

```
py -3.11 -m venv .venv
.\.venv\Scripts\pip.exe install -r requirements.txt
```

### liboqs (C library for `liboqs-python`)

On first import, `liboqs-python` tries to build liboqs from source, which needs CMake and MSVC.
Instead we use a prebuilt liboqs **0.16.0** DLL, the same version as `liboqs-python 0.16.0.1`:

| | |
|---|---|
| Package | MSYS2 `mingw-w64-ucrt-x86_64-liboqs-0.16.0-1` |
| Download | https://mirror.msys2.org/mingw/ucrt64/mingw-w64-ucrt-x86_64-liboqs-0.16.0-1-any.pkg.tar.zst |
| Package page | https://packages.msys2.org/base/mingw-w64-liboqs |
| File used | `ucrt64/bin/liboqs-9.dll` from the package, saved as `vendor/liboqs/bin/oqs.dll` |
| SHA256 of `oqs.dll` | `14EDAEBF965ED55372B144F35656D6EE3A2C4868E1BB82D4EE07C6D788C015C9` |
| License | MIT (`vendor/liboqs/LICENSE`) |

The DLL has no runtime dependencies beyond Windows system DLLs. To point `oqs` at it, add this one
line as a `.pth` file in the venv (we use `.venv/Lib/site-packages/pqgate_oqs_path.pth`):

```
import os; os.environ.setdefault('OQS_INSTALL_PATH', r'<path-to>\pq-gate\vendor\liboqs')
```

Verify the setup:

```
.\.venv\Scripts\python.exe scripts\smoke_test_oqs.py      # ML-KEM-768 + ML-DSA-65
.\.venv\Scripts\python.exe scripts\check_api_card.py      # API card in the prompt runs
.\.venv\Scripts\python.exe scripts\smoke_test_ollama.py   # both models reply
```

### Models (Ollama)

```
ollama pull gemma3:4b
ollama pull qwen2.5-coder:3b
```
