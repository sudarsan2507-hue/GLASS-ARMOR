"""Paper-dossier analysis: derive every number from EXISTING result files only (no experiments).

Inputs : results/tables/*.csv|json, results/raw/*/*/sample_*.json, results/repair/**/round_*.json,
         labeling/labels_ai.csv, results/labeling_key.csv, benchmark/*/meta.yaml, benchmark/*/original.py
Outputs: paper_dossier/numbers.csv, paper_dossier/tables/derived_*.csv (+ .tex)
Usage  : python scripts/dossier/compute_stats.py
"""
import csv
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "paper_dossier"
TAB = OUT / "tables"
T = ROOT / "results" / "tables"
SCRIPT = "scripts/dossier/compute_stats.py"
NUMBERS = []


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def num(id_, value, meaning, source):
    NUMBERS.append({"id": id_, "value": value, "meaning": meaning, "source": source, "script": SCRIPT})


def prop(id_, k, n, meaning, source):
    lo, hi = wilson(k, n)
    pct = f"{100 * k / n:.1f}%" if n else "n/a"
    num(id_, f"{k}/{n} = {pct} (95% Wilson CI {100 * lo:.1f}-{100 * hi:.1f}%)", meaning, source)
    return k, n, lo, hi


def read(path):
    return list(csv.DictReader(open(path, encoding="utf-8")))


def write_table(name, rows, caption):
    TAB.mkdir(parents=True, exist_ok=True)
    with open(TAB / f"{name}.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    esc = lambda s: str(s).replace("_", r"\_").replace("%", r"\%").replace("&", r"\&").replace("#", r"\#")
    cols = list(rows[0])
    tex = [r"\begin{table}[t]", r"\centering", rf"\caption{{{esc(caption)}}}", r"\small",
           r"\begin{tabular}{" + "l" * len(cols) + "}", r"\hline",
           " & ".join(esc(c) for c in cols) + r" \\", r"\hline"]
    tex += [" & ".join(esc(r[c]) for c in cols) + r" \\" for r in rows]
    tex += [r"\hline", r"\end{tabular}", r"\end{table}"]
    (TAB / f"{name}.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def _corrected_fail(r):  # A2 naming bug: gpt-oss task_20 rows whose only flag is A2 (manually verified, PROGRESS.md)
    if r["gate_verdict"] != "FAIL":
        return False
    return not (r["model"] == "openai/gpt-oss-120b" and r["task"] == "task_20_suite_negotiation" and r["gate_flags"] == "A2")


def _is_true(r, field):
    return r[field] == "True"


# ---------- benchmark ----------
def _task_row(d, bv):
    meta = yaml.safe_load((d / "meta.yaml").read_text(encoding="utf-8"))
    orig = (d / "original.py").read_text(encoding="utf-8")
    tests_src = (d / "test_original.py").read_text(encoding="utf-8")
    n_tests = next(int(r["passed"]) for r in bv if r["task"] == d.name and r["kind"] == "original")
    return {
        "task": d.name, "family": meta["family"], "family_name": meta["family_name"],
        "original_lines": len(orig.splitlines()), "tests": n_tests,
        "test_functions": "; ".join(re.findall(r"^def (test_\w+)", tests_src, re.M)),
        "variants_total": len(meta["variants"]),
        "variants_held_out": sum(bool(v.get("held_out")) for v in meta["variants"]),
        "flaws": " ".join(v["flaw"] for v in meta["variants"]),
        "classical": meta.get("classical", ""), "pqc": " ".join(str(meta.get("pqc", "")).split()),
    }


def benchmark_section():
    bv = read(T / "benchmark_validation.csv")
    tasks = [_task_row(d, bv) for d in sorted((ROOT / "benchmark").glob("task_*"))]
    write_table("derived_benchmark_tasks", tasks, "The 20 benchmark tasks")
    lines = [t["original_lines"] for t in tasks]
    num("bench_tasks", len(tasks), "benchmark tasks", "benchmark/*/meta.yaml")
    num("bench_orig_lines_min_max", f"{min(lines)}-{max(lines)}",
        "lines in original.py (min-max)", "benchmark/*/original.py")
    num("bench_tests_total", sum(t["tests"] for t in tasks), "functional tests over all tasks (pytest count on original.py)",
        "results/tables/benchmark_validation.csv")
    num("bench_variants_total", sum(t["variants_total"] for t in tasks), "broken variants incl. held-out", "benchmark/*/meta.yaml")
    num("bench_variants_heldout", sum(t["variants_held_out"] for t in tasks), "held-out variants", "benchmark/*/meta.yaml")
    broken = [r for r in bv if r["kind"] == "broken"]
    prop("bench_test_invisible", sum(r["all_tests_pass"] == "True" for r in broken), len(broken),
         "original 71 broken variants passing all tests (test-invisible)", "results/tables/benchmark_validation.csv")
    refs = [r for r in bv if r["kind"] in ("original", "reference")]
    refs_ok = sum(r["all_tests_pass"] == "True" for r in refs)
    num("bench_orig_ref_pass", f"{refs_ok}/40", "originals + references passing all tests", "results/tables/benchmark_validation.csv")


# ---------- gate validation (in-sample, 71 variants / 20 references) ----------
TOOLS = ("tests", "semgrep", "bandit", "gate")


def _gate_ci_row(r):
    n = int(r["variants"])
    row = {"flaw": r["flaw"], "variants": n}
    for tool in TOOLS:
        k = int(r[tool])
        lo, hi = wilson(k, n)
        row[tool] = f"{k}/{n} ({100*lo:.0f}-{100*hi:.0f}%)"
    return row


def gate_section():
    gf = read(T / "gate_by_flaw.csv")
    rows = [_gate_ci_row(r) for r in gf if not r["flaw"].startswith("FP")]
    write_table("derived_gate_validation_ci", rows, "In-sample detection on the 71 benchmark variants (95% Wilson CI)")
    allrow = next(r for r in gf if r["flaw"] == "all")
    for tool in TOOLS:
        prop(f"val_{tool}_detect", int(allrow[tool]), 71, f"variants flagged by {tool} (in-sample)", "results/tables/gate_by_flaw.csv")
    fprow = next(r for r in gf if r["flaw"].startswith("FP"))
    for tool in TOOLS:
        prop(f"val_{tool}_fp", int(fprow[tool]), 20, f"references flagged by {tool} (false positives)", "results/tables/gate_by_flaw.csv")

    held = json.loads((T / "gate_heldout_2026-10-14.json").read_text(encoding="utf-8"))
    prop("heldout_caught", sum(h["caught_expected"] for h in held), len(held), "held-out variants caught by an expected check",
         "results/tables/gate_heldout_2026-10-14.json")
    for fl in ("F4", "F8"):
        hs = [h for h in held if h["flaw"] == fl]
        prop(f"heldout_{fl}", sum(h["caught_expected"] for h in hs), len(hs), f"held-out {fl} caught", "results/tables/gate_heldout_2026-10-14.json")


# ---------- phase 3 ----------
def _count(rows, pred):
    return sum(1 for r in rows if pred(r))


def _phase3_row(m, ev):
    rs = [r for r in ev if m == "ALL" or r["model"] == m]
    passing = [r for r in rs if _is_true(r, "all_tests_pass")]
    pop = [r for r in passing if _is_true(r, "uses_oqs")]
    spop = [r for r in passing if _is_true(r, "really_uses_oqs")]
    s2pop = [r for r in spop if _is_true(r, "uses_oqs")]  # imports AND calls liboqs in a function
    frozen = lambda r: r["gate_verdict"] == "FAIL"  # noqa: E731
    return {"model": m, "samples": len(rs), "parse": _count(rs, lambda r: _is_true(r, "syntax_ok")),
            "pass_tests": len(passing), "pass_and_imports_oqs": len(pop), "pass_and_strict_migrated": len(spop),
            "gate_fail_frozen": _count(pop, frozen),
            "gate_fail_corrected": _count(pop, _corrected_fail),
            "gate_fail_strict_frozen": _count(spop, frozen),
            "gate_fail_strict_corrected": _count(spop, _corrected_fail),
            "pass_and_imports_and_calls_oqs": len(s2pop),
            "gate_fail_imports_and_calls_corrected": _count(s2pop, _corrected_fail),
            "semgrep_flags_on_pop": _count(pop, lambda r: int(r["semgrep_default_findings"] or 0) > 0),
            "bandit_flags_on_pop": _count(pop, lambda r: int(r["bandit_findings"] or 0) > 0),
            "pass_tests_not_importing_oqs": _count(passing, lambda r: r["uses_oqs"] != "True"),
            "pass_tests_not_strict_migrated": _count(passing, lambda r: r["really_uses_oqs"] != "True")}


def _phase3_numbers(m, row):
    tag = m.replace("/", "_").replace(":", "_").replace(".", "")
    src = "results/tables/phase3_eval_strict.csv"
    prop(f"p3_{tag}_pass", row["pass_tests"], row["samples"], f"{m}: outputs passing all tests", src)
    prop(f"p3_{tag}_fail_frozen", row["gate_fail_frozen"], row["pass_and_imports_oqs"], f"{m}: gate FAIL among test-passing liboqs-importing outputs (frozen gate)", src)
    prop(f"p3_{tag}_fail_corrected", row["gate_fail_corrected"], row["pass_and_imports_oqs"], f"{m}: same, after A2 naming-bug correction", src)
    prop(f"p3_{tag}_fail_strict_corr", row["gate_fail_strict_corrected"], row["pass_and_strict_migrated"], f"{m}: gate FAIL among strictly migrated test-passing outputs (corrected)", src)
    prop(f"p3_{tag}_fail_imp_calls_corr", row["gate_fail_imports_and_calls_corrected"], row["pass_and_imports_and_calls_oqs"], f"{m}: gate FAIL among test-passing outputs that import AND call liboqs in a function (corrected)", src)
    num(f"p3_{tag}_classical_pass", row["pass_tests_not_importing_oqs"], f"{m}: outputs passing all tests without importing liboqs", src)
    num(f"p3_{tag}_baselines", f"semgrep {row['semgrep_flags_on_pop']}, bandit {row['bandit_flags_on_pop']} of {row['pass_and_imports_oqs']}", f"{m}: baselines on test-passing liboqs outputs", src)


def _phase3_clusters(ev):
    pop = [r for r in ev if r["all_tests_pass"] == "True" and r["uses_oqs"] == "True"]
    groups = defaultdict(lambda: {"pop": 0, "fail_frozen": 0, "fail_corrected": 0, "flags": Counter()})
    for r in pop:
        g = groups[(r["model"], r["task"])]
        g["pop"] += 1
        g["fail_frozen"] += r["gate_verdict"] == "FAIL"
        g["fail_corrected"] += _corrected_fail(r)
        for f in filter(None, r["gate_flags"].split("|")):
            g["flags"][f] += 1
    return [{"model": m, "task": t, "test_passing_oqs_outputs": g["pop"], "gate_fail_frozen": g["fail_frozen"],
             "gate_fail_corrected": g["fail_corrected"], "flags": " ".join(f"{k}x{v}" for k, v in sorted(g["flags"].items()))}
            for (m, t), g in sorted(groups.items())]


def phase3_section(ev):
    p3 = []
    for m in sorted({r["model"] for r in ev}) + ["ALL"]:
        row = _phase3_row(m, ev)
        p3.append(row)
        _phase3_numbers(m, row)
    write_table("derived_phase3_per_model", p3, "Phase 3: 400 migrations per model")

    # gemma: strict count > import count -> list files calling oqs without importing it
    odd = [f"{r['model']} {r['task']} s{r['sample']}" for r in ev if r["really_uses_oqs"] == "True" and r["uses_oqs"] != "True" and r["all_tests_pass"] == "True"]
    num("p3_strict_without_import", f"{len(odd)}: " + "; ".join(odd), "test-passing outputs that call oqs.* in a function but have no 'import oqs' line", "results/tables/phase3_eval_strict.csv")

    # per-task clustering
    cl = _phase3_clusters(ev)
    write_table("derived_phase3_per_task", cl, "Phase 3: flags per (model, task)")
    num("p3_groups_flagged_frozen", sum(c["gate_fail_frozen"] > 0 for c in cl), "(model, task) groups with >=1 gate FAIL (frozen)", "results/tables/phase3_eval_strict.csv")
    num("p3_groups_flagged_corrected", sum(c["gate_fail_corrected"] > 0 for c in cl), "(model, task) groups with >=1 gate FAIL (corrected)", "results/tables/phase3_eval_strict.csv")
    num("p3_tasks_flagged_corrected", len({c["task"] for c in cl if c["gate_fail_corrected"] > 0}), "distinct tasks with >=1 corrected gate FAIL", "results/tables/phase3_eval_strict.csv")
    num("p3_groups_total", len(cl), "(model, task) groups with >=1 test-passing liboqs output", "results/tables/phase3_eval_strict.csv")


# ---------- labels ----------
def _confusion(items, gate_fn, key, evk):
    tp = fp = fn = tn = 0
    for r in items:
        k = key[r["item"]]
        g = gate_fn(evk[(k["model"], k["task"], k["sample"])])
        ins = r["secure"] == "no"
        tp += g and ins; fp += g and not ins; fn += (not g) and ins; tn += (not g) and not ins
    return tp, fp, fn, tn


def _f1(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0
    rc = tp / (tp + fn) if tp + fn else 0
    return 2 * p * rc / (p + rc) if p + rc else 0


def _label_numbers(scope, ver, items, gate_fn, key, evk):
    tp, fp, fn, tn = _confusion(items, gate_fn, key, evk)
    src = "labeling/labels_ai.csv + results/labeling_key.csv + results/tables/phase3_eval_strict.csv"
    num(f"lab_{scope}_{ver}_confusion", f"TP {tp} FP {fp} FN {fn} TN {tn} (n={len(items)})", f"gate vs AI labels, {scope} items, {ver} gate", src)
    prop(f"lab_{scope}_{ver}_precision", tp, tp + fp, f"precision, {scope} items, {ver} gate", src)
    prop(f"lab_{scope}_{ver}_recall", tp, tp + fn, f"recall, {scope} items, {ver} gate", src)
    prop(f"lab_{scope}_{ver}_fpr", fp, fp + tn, f"false positive rate, {scope} items, {ver} gate", src)
    num(f"lab_{scope}_{ver}_f1", f"{_f1(tp, fp, fn):.3f}", f"F1, {scope} items, {ver} gate", src)


UNMIGRATED = re.compile(r"not migrated|never actually migrated|oqs imported but unused|imported but unused")


def labels_section(ev):
    lab = read(ROOT / "labeling" / "labels_ai.csv")
    key = {r["item"]: r for r in read(ROOT / "results" / "labeling_key.csv")}
    evk = {(r["model"], r["task"], r["sample"]): r for r in ev}
    unmig = {r["item"] for r in lab if UNMIGRATED.search((r["other_flaw"] + " " + r["notes"]).lower())}
    verdicts = Counter(r["secure"] for r in lab)
    num("lab_items", len(lab), "blind-labelled items", "labeling/labels_ai.csv")
    num("lab_counts", f"secure {verdicts['yes']}, insecure {verdicts['no']}, unsure {verdicts['unsure']}", "AI label verdicts", "labeling/labels_ai.csv")
    num("lab_unmigrated_items", f"{len(unmig)}: {' '.join(sorted(unmig))}", "items the labeller marked as not actually migrated (text match on its notes)", "labeling/labels_ai.csv")

    for scope, items in (("all", lab), ("real", [r for r in lab if r["item"] not in unmig])):
        for ver, fn_ in (("frozen", lambda e: e["gate_verdict"] == "FAIL"), ("corrected", _corrected_fail)):
            _label_numbers(scope, ver, items, fn_, key, evk)


# ---------- repair ----------
def _repair_row(cond, m, its):
    return {"condition": cond, "model": m, "items": len(its), "fixed": _count(its, lambda i: _is_true(i, "fixed")),
            "broke_tests": _count(its, lambda i: _is_true(i, "broke_tests")),
            "never_changed": _count(its, lambda i: _is_true(i, "never_changed")),
            "rounds_1/2/3": "/".join(str(_count(its, lambda i, k=k: i["rounds"] == str(k))) for k in (1, 2, 3))}


def _repair_by_check(items):
    pc = []
    for cond in ("tests", "gate"):
        tot, fixed = Counter(), Counter()
        for i in (x for x in items if x["condition"] == cond):
            for c in set(filter(None, i["start_flags"].split("|"))):
                tot[c] += 1
                fixed[c] += i["fixed"] == "True"
        pc.extend({"condition": cond, "start_check": c, "items_with_check": tot[c], "items_fixed": fixed[c]} for c in sorted(tot))
    return pc


def _mcnemar_p(b, c):
    n = b + c
    return min(1.0, 2 * sum(math.comb(n, k) for k in range(0, min(b, c) + 1)) / 2 ** n) if n else 1.0


def repair_section():
    items = read(T / "repair_items.csv")
    rep = []
    for cond in ("tests", "gate"):
        for m in sorted({i["model"] for i in items}) + ["ALL"]:
            its = [i for i in items if i["condition"] == cond and (m == "ALL" or i["model"] == m)]
            if its:
                rep.append(_repair_row(cond, m, its))
    write_table("derived_repair", rep, "Phase 4 repair outcomes")
    for r in rep:
        if r["model"] in ("ALL", "openai_gpt-oss-120b"):
            prop(f"rep_{r['condition']}_{r['model']}_fixed", r["fixed"], r["items"], f"repair fixed, condition {r['condition']}, {r['model']}", "results/tables/repair_items.csv")
    # per starting check
    write_table("derived_repair_by_check", _repair_by_check(items), "Phase 4: items fixed by starting gate check")
    _repair_pair_numbers(items)


def _repair_pair_numbers(items):
    """McNemar (exact) tests vs gate, paired on the same items."""
    pair = defaultdict(dict)
    for i in items:
        pair[(i["model"], i["task"], i["sample"])][i["condition"]] = i["fixed"] == "True"
    b = sum(1 for v in pair.values() if v.get("gate") and not v.get("tests"))
    c = sum(1 for v in pair.values() if v.get("tests") and not v.get("gate"))
    pval = _mcnemar_p(b, c)
    num("rep_mcnemar", f"discordant: gate-only fixed {b}, tests-only fixed {c}; exact two-sided p = {pval:.4f}", "McNemar exact test, gate vs tests feedback, 31 paired items", "results/tables/repair_items.csv")
    nb = sum(1 for (m, t, s), v in pair.items() if m == "openai_gpt-oss-120b" and t == "task_20_suite_negotiation")
    num("rep_task20_items", nb, "repair items that were A2 naming-bug false alarms (gpt-oss task_20)", "results/tables/repair_items.csv")


# ---------- runtime / API usage ----------
def runtime_section():
    dur, groq_tok, rep_dur = Counter(), Counter(), Counter()
    for p in (ROOT / "results" / "raw").glob("*/*/sample_*.json"):
        d = json.loads(p.read_text(encoding="utf-8"))
        dur[d["model"]] += d.get("duration_s") or 0
        usage = d.get("usage")
        if usage:
            groq_tok["prompt"] += usage.get("prompt_tokens", 0)
            groq_tok["completion"] += usage.get("completion_tokens", 0)
    for p in (ROOT / "results" / "repair").glob("*/*/*/sample_*/round_[1-9].json"):
        d = json.loads(p.read_text(encoding="utf-8"))
        rep_dur[d["model"]] += d.get("duration_s") or 0
    for m, s in sorted(dur.items()):
        num(f"runtime_gen_{m}", f"{s/3600:.1f} h", f"summed generation time, Phase 3, {m}", "results/raw/*/*/sample_*.json (duration_s)")
    num("groq_tokens_phase3", f"prompt {groq_tok['prompt']}, completion {groq_tok['completion']}", "Groq token usage, Phase 3 gpt-oss", "results/raw/openai_gpt-oss-120b/*/sample_*.json (usage)")
    for m, s in sorted(rep_dur.items()):
        num(f"runtime_repair_{m}", f"{s/3600:.2f} h", f"summed generation time, Phase 4, {m}", "results/repair/**/round_*.json (duration_s)")
    num("groq_tokens_phase4", "UNVERIFIED", "Groq token usage in Phase 4 (repair.py did not log usage)", "harness/repair.py")


def main():
    benchmark_section()
    gate_section()
    ev = read(T / "phase3_eval_strict.csv")
    phase3_section(ev)
    labels_section(ev)
    repair_section()
    runtime_section()

    OUT.mkdir(exist_ok=True)
    with open(OUT / "numbers.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["id", "value", "meaning", "source", "script"])
        w.writeheader()
        w.writerows(NUMBERS)
    print(f"{len(NUMBERS)} numbers -> paper_dossier/numbers.csv; tables -> paper_dossier/tables/")


if __name__ == "__main__":
    main()
