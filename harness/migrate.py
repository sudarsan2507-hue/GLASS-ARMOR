"""Ask each model to migrate each benchmark task to PQC, and save every raw output.

Models come from config.yaml. Local models run through Ollama; a model with
`provider: groq` runs through the Groq API (key read from .env, never logged).

Usage:
    python harness/migrate.py                       # all tasks x all models x N samples
    python harness/migrate.py --models qwen2.5-coder:3b --tasks task_01_file_key_wrap
    python harness/migrate.py --dry-run             # only show what would run

Resumable: a sample is skipped if its JSON log already exists. The log is written last,
so a crash mid-sample just redoes that one sample. Timeouts and errors are logged too
(status "timeout"/"error") and count as done, so they are never silently dropped or retried
on resume. Delete a sample's .json to force a redo.
"""
import argparse
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG = yaml.safe_load((ROOT / "config.yaml").read_text())
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def build_prompt(original_code):
    """Fixed prompt: instruction + API card + the original file. Same for every model."""
    p = CONFIG["prompts"]
    return f"{p['migrate']}\n\n{p['api_card']}\n```python\n{original_code}\n```\n"


def extract_code(response):
    """Strip markdown fences if present. Takes the longest fenced block, else the whole text.
    The full raw response is always saved in the JSON log as well."""
    blocks = re.findall(r"```[a-zA-Z0-9_+-]*\n(.*?)```", response, flags=re.DOTALL)
    if blocks:
        return max(blocks, key=len)
    return response


def call_ollama(model, prompt, seed):
    """One generation request. Returns (status, response_json_or_None, error_text)."""
    gen = CONFIG["generation"]
    body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": gen["temperature"], "seed": seed, "num_ctx": gen["num_ctx"],
                    "num_predict": gen["num_predict"]},
    }
    url = f"{CONFIG['ollama']['url']}/api/generate"
    attempts = 1 + CONFIG["ollama"]["retries_on_timeout"]
    for attempt in range(1, attempts + 1):
        try:
            r = requests.post(url, json=body, timeout=CONFIG["ollama"]["timeout_s"])
            r.raise_for_status()
            return "ok", r.json(), ""
        except requests.Timeout:
            print(f"    timeout (attempt {attempt}/{attempts})")
        except requests.RequestException as e:
            return "error", None, str(e)
    return "timeout", None, f"timed out {attempts}x at {CONFIG['ollama']['timeout_s']}s"


def groq_key():
    """Read GROQ_API_KEY from the project's .env file."""
    env = ROOT / ".env"
    m = re.search(r"^GROQ_API_KEY=(\S+)\s*$", env.read_text(encoding="utf-8"), re.M) if env.exists() else None
    if not m:
        raise SystemExit("GROQ_API_KEY missing in .env")
    return m.group(1)


class StopRun(Exception):
    """Infrastructure problem (daily rate limit, network down): stop without writing a sample."""


def call_groq(entry, prompt, seed, key):
    """One chat completion on Groq. Rate limits, server errors and dropped connections are
    infrastructure: short ones are waited out and retried; a long rate limit (daily cap) or
    repeated failures raise StopRun so no sample is written and the run can resume later.
    Only a definite API rejection (other 4xx) is recorded as status "error"."""
    body = {
        "model": entry["name"],
        "messages": [{"role": "user", "content": prompt}],
        "temperature": CONFIG["generation"]["temperature"],
        "seed": seed,
        "max_completion_tokens": entry["max_completion_tokens"],
    }
    headers = {"Authorization": f"Bearer {key}"}
    for attempt in range(1, 11):
        try:
            r = requests.post(GROQ_URL, json=body, headers=headers, timeout=entry.get("timeout_s", 300))
        except requests.RequestException as e:
            print(f"    network problem ({type(e).__name__}), retrying in 30s (attempt {attempt})")
            time.sleep(30)
            continue
        if r.status_code == 429 or r.status_code >= 500:
            wait = float(r.headers.get("retry-after", 20))
            if wait > 300:
                raise StopRun(f"rate limit asks to wait {wait:.0f}s (daily cap?)")
            print(f"    HTTP {r.status_code}, waiting {wait:.0f}s (attempt {attempt})")
            time.sleep(wait + 1)
            continue
        if not r.ok:
            return "error", None, f"HTTP {r.status_code}: {r.text[:300]}"
        return "ok", r.json(), ""
    raise StopRun("10 failed attempts (network or server)")


def model_dir_name(model):
    return model.replace(":", "_").replace("/", "_")  # not allowed in Windows folder names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", help="subset of models from config.yaml")
    ap.add_argument("--tasks", nargs="*", help="subset of task folder names")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    entries = {m["name"]: m for m in CONFIG["models"]}
    models = args.models or list(entries)
    bench = ROOT / CONFIG["paths"]["benchmark"]
    tasks = sorted(d.name for d in bench.glob("task_*") if d.is_dir())
    if args.tasks:
        tasks = [t for t in tasks if t in args.tasks]
    seeds = CONFIG["generation"]["seeds"][: CONFIG["generation"]["samples_per_task"]]

    local = [m for m in models if entries[m].get("provider", "ollama") == "ollama"]
    model_info, ollama_version = {}, None
    if local:
        installed = requests.get(f"{CONFIG['ollama']['url']}/api/tags", timeout=30).json()["models"]
        model_info = {m["name"]: m for m in installed}
        ollama_version = requests.get(f"{CONFIG['ollama']['url']}/api/version", timeout=30).json()["version"]
        print(f"Ollama version: {ollama_version}")
    key = groq_key() if any(entries[m].get("provider") == "groq" for m in models) else None

    total, done, skipped = len(models) * len(tasks) * len(seeds), 0, 0
    print(f"Plan: {len(models)} models x {len(tasks)} tasks x {len(seeds)} samples = {total}")
    for model in models:
        entry = entries[model]
        provider = entry.get("provider", "ollama")
        if provider == "ollama" and model not in model_info:
            raise SystemExit(f"Model {model} is not installed in Ollama")
        for task in tasks:
            original = (bench / task / "original.py").read_text()
            prompt = build_prompt(original)
            out_dir = ROOT / CONFIG["paths"]["raw_outputs"] / model_dir_name(model) / task
            for i, seed in enumerate(seeds):
                log_path = out_dir / f"sample_{i}.json"
                if log_path.exists():
                    skipped += 1
                    continue
                print(f"[{model}] {task} sample_{i} (seed {seed})")
                if args.dry_run:
                    continue
                out_dir.mkdir(parents=True, exist_ok=True)
                start = time.time()
                log = {"model": model, "provider": provider, "task": task, "sample": i, "seed": seed,
                       "temperature": CONFIG["generation"]["temperature"], "prompt": prompt}
                if provider == "groq":
                    try:
                        status, resp, error = call_groq(entry, prompt, seed, key)
                    except StopRun as e:
                        print(f"    STOPPED, no sample written: {e}. Resume later with the same command.")
                        print(f"Stopped: {done} new, {skipped} already done (skipped), {total} total")
                        return
                    choice = resp["choices"][0] if resp else {}
                    raw = (choice.get("message") or {}).get("content") or ""
                    log.update({
                        "api_model_id": resp.get("model") if resp else None,
                        "system_fingerprint": resp.get("system_fingerprint") if resp else None,
                        "max_completion_tokens": entry["max_completion_tokens"],
                        "usage": resp.get("usage") if resp else None,
                        "done_reason": choice.get("finish_reason"),  # "length" = hit the token cap
                        "reasoning": (choice.get("message") or {}).get("reasoning"),
                    })
                else:
                    status, resp, error = call_ollama(model, prompt, seed)
                    raw = resp["response"] if resp else ""
                    info = model_info[model]
                    log.update({
                        "tag": model.split(":")[-1],
                        "digest": info["digest"],
                        "ollama_version": ollama_version,
                        "size_bytes": info["size"],
                        "num_ctx": CONFIG["generation"]["num_ctx"],
                        "num_predict": CONFIG["generation"]["num_predict"],
                        "timeout_s": CONFIG["ollama"]["timeout_s"],
                        "eval_count": resp.get("eval_count") if resp else None,
                        "done_reason": resp.get("done_reason") if resp else None,  # "length" = hit num_predict
                    })
                code = extract_code(raw) if raw else ""
                # Write the code first, the log last (log present = sample complete)
                (out_dir / f"sample_{i}.py").write_text(code, encoding="utf-8")
                log.update({
                    "status": status,
                    "error": error,
                    "raw_response": raw,
                    "fences_stripped": code != raw,
                    "duration_s": round(time.time() - start, 1),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                log_path.write_text(json.dumps(log, indent=2), encoding="utf-8")
                done += 1
                print(f"    {status} in {log['duration_s']}s")
    print(f"Finished: {done} new, {skipped} already done (skipped), {total} total")


if __name__ == "__main__":
    main()
