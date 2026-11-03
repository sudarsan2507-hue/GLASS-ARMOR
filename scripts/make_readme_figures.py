"""Draw the README figures (light + dark PNG) from the project's recorded results only.

Sources: results/tables/{gate_by_flaw,benchmark_flaw_counts,phase3_eval_strict,repair_items}.csv,
labeling/labels_ai.csv + results/labeling_key.csv, paper_dossier/code_examples/ (real model output).
Palette: validated reference palette (CVD- and contrast-checked for both surfaces).
Usage: python scripts/make_readme_figures.py
"""
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap, to_rgb  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "images"
T = ROOT / "results" / "tables"
plt.rcParams["font.family"] = ["Segoe UI", "DejaVu Sans"]

THEMES = {
    "light": dict(bg="#fcfcfb", ink="#0b0b0b", ink2="#52514e", muted="#898781", grid="#e1e0d9", base="#c3c2b7",
                  blue="#2a78d6", orange="#eb6834", neutral="#c3c2b7", box="#f3f2ee", empty="#f0efec",
                  seq=["#eef4fc", "#b7d3f6", "#6da7ec", "#2a78d6", "#184f95"], code="#f6f5f2"),
    "dark": dict(bg="#1a1a19", ink="#f0efec", ink2="#c3c2b7", muted="#898781", grid="#2c2c2a", base="#383835",
                 blue="#3987e5", orange="#d95926", neutral="#5a5955", box="#232322", empty="#232322",
                 seq=["#1f2633", "#184f95", "#256abf", "#3987e5", "#86b6ef"], code="#212120"),
}
FLAW_NAMES = {
    "F1": "Raw KEM secret used as AES key", "F2": "Hybrid combiner without binding",
    "F3": "Classical fallback still reachable", "F4": "Only classical half decides (hybrid)",
    "F5": "Key material leaked to logs / files", "F6": "Weak or fixed randomness",
    "F7": "Signature binds the wrong data", "F8": "Non-constant-time MAC comparison",
    "F9": "Downgrade via preference order", "F10": "AES-GCM nonce reuse",
}
MODELS = [("gemma3:4b", "gemma3 4B"), ("qwen2.5-coder:3b", "qwen2.5-coder 3B"),
          ("qwen2.5-coder:7b", "qwen2.5-coder 7B"), ("openai/gpt-oss-120b", "gpt-oss 120B")]


def read(path):
    return list(csv.DictReader(open(path, encoding="utf-8")))


def corrected_fail(r):
    """Frozen-gate FAIL minus the 5 documented A2 suite-name false alarms (gpt-oss task_20)."""
    return r["gate_verdict"] == "FAIL" and not (
        r["model"] == "openai/gpt-oss-120b" and r["task"] == "task_20_suite_negotiation" and r["gate_flags"] == "A2")


def lum(hex_):
    r, g, b = to_rgb(hex_)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def new_fig(t, w, h):
    fig = plt.figure(figsize=(w, h), facecolor=t["bg"])
    return fig


def header(fig, t, kicker, main, sub):
    fig.text(0.03, 0.955, kicker.upper(), fontsize=9, color=t["blue"], fontweight="bold", va="top")
    fig.text(0.03, 0.905, main, fontsize=15, color=t["ink"], fontweight="bold", va="top")
    fig.text(0.03, 0.835, sub, fontsize=10, color=t["ink2"], va="top")


def footer(fig, t, text):
    fig.text(0.03, 0.025, text, fontsize=8, color=t["muted"], va="bottom")


def style(ax, t, grid_axis="x"):
    ax.set_facecolor(t["bg"])
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(t["base"])
    ax.tick_params(colors=t["ink2"], length=0, labelsize=10)
    if grid_axis:
        getattr(ax, f"{grid_axis}axis").grid(True, color=t["grid"], linewidth=0.8)
    ax.set_axisbelow(True)


def save(fig, name, mode):
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"{name}-{mode}.png", dpi=200, facecolor=fig.get_facecolor())
    plt.close(fig)


# ------------------------------------------------------------------ data
def load():
    gf = {r["flaw"]: r for r in read(T / "gate_by_flaw.csv")}
    counts = {r["flaw"]: int(r["total"]) for r in read(T / "benchmark_flaw_counts.csv")}
    ev = read(T / "phase3_eval_strict.csv")
    rep = read(T / "repair_items.csv")
    labels = read(ROOT / "labeling" / "labels_ai.csv")
    key = {r["item"]: r for r in read(ROOT / "results" / "labeling_key.csv")}
    return gf, counts, ev, rep, labels, key


# ------------------------------------------------------------------ figures
def hero(t, mode, gf, ev, rep):
    passing = [r for r in ev if r["all_tests_pass"] == "True"]
    pop = [r for r in passing if r["uses_oqs"] == "True"]
    flagged = sum(corrected_fail(r) for r in pop)
    fixed_gate = sum(r["fixed"] == "True" for r in rep if r["condition"] == "gate")
    fixed_tests = sum(r["fixed"] == "True" for r in rep if r["condition"] == "tests")
    fig = new_fig(t, 12, 3.3)
    fig.add_artist(Rectangle((0.03, 0.18), 0.006, 0.64, transform=fig.transFigure, color=t["blue"]))
    fig.text(0.055, 0.74, "GLASS ARMOR", fontsize=30, fontweight="bold", color=t["ink"], va="center")
    fig.text(0.055, 0.53, "Passing tests, failing security in", fontsize=13, color=t["ink2"], va="center")
    fig.text(0.055, 0.42, "LLM-driven post-quantum migrations", fontsize=13, color=t["ink2"], va="center")
    fig.text(0.055, 0.24, "BENCHMARK   |   MEASUREMENT STUDY   |   SECURITY GATE", fontsize=8.5,
             color=t["blue"], fontweight="bold", va="center")
    stats = [(f"0 / {gf['all']['variants']}", "planted flaws caught by\nthe functional tests"),
             (f"{flagged} / {len(pop)}", "working AI migrations\nflagged insecure"),
             (f"{fixed_tests} vs {fixed_gate}", "flaws fixed with test vs\ngate feedback")]
    for i, (big, small) in enumerate(stats):
        x = 0.535 + i * 0.155
        fig.add_artist(Rectangle((x - 0.012, 0.2), 0.0015, 0.6, transform=fig.transFigure, color=t["base"]))
        fig.text(x, 0.6, big, fontsize=24, fontweight="bold", color=t["orange"] if i == 1 else t["ink"], va="center")
        fig.text(x, 0.36, small, fontsize=9.5, color=t["ink2"], va="center", linespacing=1.35)
    save(fig, "hero", mode)


def architecture(t, mode):
    fig = new_fig(t, 12, 5.0)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 120)
    ax.set_ylim(0, 50)
    ax.axis("off")

    def panel(x, y, w, h, edge=None, lw=1.2, fill=None):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=1.2",
                                    facecolor=fill or t["box"], edgecolor=edge or t["base"], linewidth=lw))

    def arrow(p, q, color=None, rad=0.0):
        ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=13, linewidth=1.5,
                                     color=color or t["muted"], connectionstyle=f"arc3,rad={rad}"))

    ax.text(2, 49.0, "PIPELINE AND GATE ARCHITECTURE", fontsize=9, color=t["blue"], fontweight="bold", va="top")
    stages = [(2, "Classical program", ["RSA-OAEP, ECDSA,", "X25519, RSA-PSS"]),
              (20, "LLM migration", ["fixed prompt + API card", "4 models, 5 seeds"]),
              (38, "Functional tests", ["198 tests, 20 tasks", "behaviour only"])]
    for x, head, lines in stages:
        panel(x, 26, 15, 14)
        ax.text(x + 7.5, 36.3, head, ha="center", fontsize=10.5, fontweight="bold", color=t["ink"])
        for k, ln in enumerate(lines):
            ax.text(x + 7.5, 31.5 - k * 2.6, ln, ha="center", fontsize=8.6, color=t["ink2"])
    arrow((17.4, 33), (19.6, 33))
    arrow((35.4, 33), (37.6, 33))
    arrow((53.4, 33), (56.6, 33))

    panel(57, 6, 44, 38, edge=t["blue"], lw=2.0)
    ax.text(79, 41.2, "Glass Armor gate", ha="center", fontsize=12, fontweight="bold", color=t["ink"])
    ax.text(79, 38.6, "runs every target in a throwaway sandbox (temp dir, subprocess, timeout)",
            ha="center", fontsize=8, color=t["ink2"])
    tiers = [(59, "STATIC TIER  (reads the code)", [("P1", "KEM output must pass a KDF"), ("P2", "no RSA / ECC left behind"),
                                                  ("P3", "no secrets in logs / files"), ("P4", "no `random` for keys"),
                                                  ("P5", "constant-time MAC compare"), ("P6", "hybrid KDF binds both secrets")]),
             (80, "ADVERSARIAL TIER  (attacks it)", [("A1", "break liboqs: fallback?"), ("A2", "offer classical: accepted?"),
                                                          ("A3", "tamper input: leak / accept?"), ("A4", "corrupt ML-KEM half"),
                                                          ("A5", "change signed fields"), ("A6", "record (key, nonce) reuse")])]
    for x, title, rows in tiers:
        panel(x, 9, 19.5, 27, fill=t["bg"])
        ax.text(x + 1, 33.6, title, fontsize=7.4, fontweight="bold", color=t["blue"])
        for k, (cid, desc) in enumerate(rows):
            yy = 30.3 - k * 3.45
            ax.text(x + 1, yy, cid, fontsize=8.6, fontweight="bold", color=t["ink"], family="monospace")
            ax.text(x + 4.2, yy, desc.replace("`", ""), fontsize=8.1, color=t["ink2"])
    ax.text(79, 6.9, "Semgrep rules  +  AST dataflow (P1, P6)  +  behavioural probes", ha="center", fontsize=7.8, color=t["muted"])

    panel(105, 30, 13, 9)
    ax.text(111.5, 35.6, "PASS", ha="center", fontsize=11, fontweight="bold", color=t["ink"])
    ax.text(111.5, 32.3, "no finding", ha="center", fontsize=8.4, color=t["ink2"])
    panel(105, 17, 13, 9, edge=t["orange"], lw=2.0)
    ax.text(111.5, 22.6, "FAIL", ha="center", fontsize=11, fontweight="bold", color=t["ink"])
    ax.text(111.5, 19.3, "checks + lines", ha="center", fontsize=8.4, color=t["ink2"])
    panel(105, 6, 13, 7)
    ax.text(111.5, 10.2, "ERROR", ha="center", fontsize=9.5, fontweight="bold", color=t["ink"])
    ax.text(111.5, 7.6, "never a silent pass", ha="center", fontsize=7.4, color=t["ink2"])
    arrow((101.4, 30), (104.6, 34))
    arrow((101.4, 24), (104.6, 21.5), color=t["orange"])
    arrow((101.4, 15), (104.6, 10.5))
    # repair loop routed above the diagram: FAIL -> right edge -> top -> down into "LLM migration"
    ax.plot([118.4, 119.6, 119.6, 27.5], [21.5, 21.5, 46.2, 46.2], color=t["orange"], linewidth=1.5,
            solid_joinstyle="round")
    ax.add_patch(FancyArrowPatch((27.5, 46.2), (27.5, 40.6), arrowstyle="-|>", mutation_scale=13, linewidth=1.5,
                                 color=t["orange"]))
    ax.text(73, 47.1, "REPAIR LOOP   findings are returned to the model (up to 3 rounds), compared against test-only feedback",
            ha="center", fontsize=8.2, color=t["ink2"])
    save(fig, "architecture", mode)


def taxonomy(t, mode, counts):
    fig = new_fig(t, 10, 4.6)
    header(fig, t, "Benchmark", "Ten flaw types, 77 test-passing broken migrations",
           "Each variant is a one-flaw edit of a correct migration that still passes 100% of its task's tests")
    ax = fig.add_axes([0.33, 0.1, 0.6, 0.66])
    style(ax, t)
    flaws = [f"F{i}" for i in range(1, 11)][::-1]
    vals = [counts[f] for f in flaws]
    ax.barh([f"{f}  {FLAW_NAMES[f]}" for f in flaws], vals, color=t["blue"], height=0.62, edgecolor=t["bg"], linewidth=2)
    for i, v in enumerate(vals):
        ax.text(v + 0.25, i, str(v), va="center", fontsize=9.5, color=t["ink"])
    ax.set_xlim(0, max(vals) * 1.12)
    for lbl in ax.get_yticklabels():
        lbl.set_color(t["ink"])
        lbl.set_fontsize(9.5)
    save(fig, "flaw-taxonomy", mode)


def detection_heatmap(t, mode, gf):
    tools = [("tests", "Functional\ntests"), ("semgrep", "Semgrep\n(default)"), ("bandit", "Bandit"), ("gate", "Glass\nArmor")]
    flaws = [f"F{i}" for i in range(1, 11)]
    fig = new_fig(t, 10, 5.6)
    header(fig, t, "Detection on the benchmark", "What each tool catches, flaw by flaw",
           "Cells: variants flagged / variants of that flaw (71 original variants; in-sample for Glass Armor)")
    ax = fig.add_axes([0.33, 0.04, 0.6, 0.63])
    cmap = LinearSegmentedColormap.from_list("seq", t["seq"])
    for i, f in enumerate(flaws):
        n = int(gf[f]["variants"])
        for j, (k, _) in enumerate(tools):
            v = int(gf[f][k])
            c = cmap(v / n) if n else t["empty"]
            ax.add_patch(Rectangle((j + 0.04, i + 0.06), 0.92, 0.88, color=c))
            col = "#0b0b0b" if lum(c[:3] if isinstance(c, tuple) else c) > 0.5 else "#ffffff"
            ax.text(j + 0.5, i + 0.5, f"{v}/{n}", ha="center", va="center", fontsize=10, color=col,
                    fontweight="bold" if k == "gate" else "normal")
    ax.set_xlim(0, len(tools))
    ax.set_ylim(len(flaws), 0)
    ax.set_xticks([j + 0.5 for j in range(len(tools))])
    ax.set_xticklabels([n for _, n in tools], fontsize=9.5, color=t["ink"])
    ax.xaxis.tick_top()
    ax.set_yticks([i + 0.5 for i in range(len(flaws))])
    ax.set_yticklabels([f"{f}  {FLAW_NAMES[f]}" for f in flaws], fontsize=9.3, color=t["ink"])
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_facecolor(t["bg"])
    save(fig, "detection-heatmap", mode)


def funnel(t, mode, ev):
    passing = [r for r in ev if r["all_tests_pass"] == "True"]
    pop = [r for r in passing if r["uses_oqs"] == "True"]
    flagged = sum(corrected_fail(r) for r in pop)
    stages = [("AI migrations generated", len(ev)), ("Pass every functional test", len(passing)),
              ("...and actually use liboqs", len(pop)), ("...flagged insecure by Glass Armor", flagged)]
    fig = new_fig(t, 10, 4.0)
    header(fig, t, "Measurement study", "400 real migrations: 4 models x 20 tasks x 5 seeds",
           f"Of {len(pop)} working PQC migrations the gate flags {flagged}; default Semgrep flagged 0 of them, Bandit 1")
    ax = fig.add_axes([0.33, 0.1, 0.6, 0.6])
    style(ax, t)
    labels = [n for n, _ in stages][::-1]
    vals = [v for _, v in stages][::-1]
    ax.barh(labels, vals, color=[t["orange"], t["blue"], t["blue"], t["blue"]], height=0.58, edgecolor=t["bg"], linewidth=2)
    for i, v in enumerate(vals):
        ax.text(v + 5, i, str(v), va="center", fontsize=10.5, color=t["ink"], fontweight="bold" if i == 0 else "normal")
    ax.set_xlim(0, max(vals) * 1.12)
    for lbl in ax.get_yticklabels():
        lbl.set_color(t["ink"])
    save(fig, "migration-funnel", mode)


def per_model(t, mode, ev):
    fig = new_fig(t, 12, 4.2)
    header(fig, t, "Per model", "Small models rarely migrate; the large model migrates but makes subtle mistakes",
           "Out of 100 migrations per model. 'Flagged' = Glass Armor FAIL among working liboqs migrations (corrected)")
    for k, (mid, name) in enumerate(MODELS):
        rs = [r for r in ev if r["model"] == mid]
        passing = [r for r in rs if r["all_tests_pass"] == "True"]
        pop = [r for r in passing if r["uses_oqs"] == "True"]
        flagged = sum(corrected_fail(r) for r in pop)
        classical = len(passing) - len(pop)
        ax = fig.add_axes([0.04 + k * 0.24, 0.12, 0.2, 0.52])
        style(ax, t, grid_axis="y")
        cats = ["pass tests", "still\nclassical", "use\nliboqs", "flagged"]
        vals = [len(passing), classical, len(pop), flagged]
        cols = [t["blue"], t["neutral"], t["blue"], t["orange"]]
        ax.bar(range(4), vals, color=cols, width=0.66, edgecolor=t["bg"], linewidth=2)
        for i, v in enumerate(vals):
            ax.text(i, v + 2, str(v), ha="center", fontsize=9.5, color=t["ink"], fontweight="bold" if i == 3 else "normal")
        ax.set_ylim(0, 100)
        ax.set_yticks([0, 25, 50, 75, 100] if k == 0 else [])
        ax.set_xticks(range(4))
        ax.set_xticklabels(cats, fontsize=8.3, color=t["ink2"])
        ax.set_title(name, fontsize=10.5, color=t["ink"], fontweight="bold", loc="left", pad=8)
    save(fig, "per-model", mode)


def task_heatmap(t, mode, ev):
    tasks = sorted({r["task"] for r in ev})
    fig = new_fig(t, 12, 4.0)
    header(fig, t, "Where the flags come from", "Flagged migrations cluster in a few tasks",
           "Cell = working liboqs migrations the gate flags (of 5 seeds). Dash = the model produced no working liboqs migration")
    ax = fig.add_axes([0.14, 0.2, 0.84, 0.48])
    cmap = LinearSegmentedColormap.from_list("seq", t["seq"])
    for i, (mid, name) in enumerate(MODELS):
        for j, task in enumerate(tasks):
            rs = [r for r in ev if r["model"] == mid and r["task"] == task and r["all_tests_pass"] == "True" and r["uses_oqs"] == "True"]
            if not rs:
                ax.add_patch(Rectangle((j + 0.05, i + 0.08), 0.9, 0.84, color=t["empty"]))
                ax.text(j + 0.5, i + 0.5, "-", ha="center", va="center", fontsize=9, color=t["muted"])
                continue
            v = sum(corrected_fail(r) for r in rs)
            c = cmap(v / 5)
            ax.add_patch(Rectangle((j + 0.05, i + 0.08), 0.9, 0.84, color=c))
            ax.text(j + 0.5, i + 0.5, str(v), ha="center", va="center", fontsize=9,
                    color="#0b0b0b" if lum(c[:3]) > 0.5 else "#ffffff", fontweight="bold" if v else "normal")
    ax.set_xlim(0, len(tasks))
    ax.set_ylim(len(MODELS), 0)
    ax.set_xticks([j + 0.5 for j in range(len(tasks))])
    ax.set_xticklabels([f"T{int(x[5:7])}" for x in tasks], fontsize=8.5, color=t["ink2"])
    ax.set_yticks([i + 0.5 for i in range(len(MODELS))])
    ax.set_yticklabels([n for _, n in MODELS], fontsize=9.5, color=t["ink"])
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_facecolor(t["bg"])
    fig.text(0.14, 0.06, "Key wrapping: T1, T4-T6     Session setup: T2, T7-T9     Document signing: T3, T10-T12     "
             "Token signing: T13-T16     Config-chosen algorithm: T17-T20", fontsize=7.8, color=t["muted"])
    save(fig, "task-heatmap", mode)


def confusion(t, mode, labels, key, ev):
    evk = {(r["model"], r["task"], r["sample"]): r for r in ev}
    unmig = {r["item"] for r in labels if re.search(r"not migrated|never actually migrated|imported but unused",
                                                     (r["other_flaw"] + " " + r["notes"]).lower())}
    m = Counter()
    for r in labels:
        if r["item"] in unmig:
            continue
        k = key[r["item"]]
        g = evk[(k["model"], k["task"], k["sample"])]["gate_verdict"] == "FAIL"
        m[(g, r["secure"] == "no")] += 1
    tp, fp, fn, tn = m[(True, True)], m[(True, False)], m[(False, True)], m[(False, False)]
    fig = new_fig(t, 8.6, 4.6)
    header(fig, t, "Ground truth", "Gate verdicts vs a blind, independent review",
           f"{tp + fp + fn + tn} real migrations reviewed by an AI labeller that never saw the gate's output (frozen gate)")
    ax = fig.add_axes([0.24, 0.1, 0.38, 0.6])
    cells = [[(tp, "true positive", t["blue"]), (fp, "false alarm", t["neutral"])],
             [(fn, "missed", t["orange"]), (tn, "true negative", t["neutral"])]]
    for i in range(2):
        for j in range(2):
            v, lab, c = cells[i][j]
            ax.add_patch(Rectangle((j + 0.03, i + 0.04), 0.94, 0.92, color=c, alpha=0.9 if c != t["neutral"] else 0.45))
            col = "#ffffff" if c in (t["blue"], t["orange"]) else t["ink"]
            ax.text(j + 0.5, i + 0.45, str(v), ha="center", va="center", fontsize=22, fontweight="bold", color=col)
            ax.text(j + 0.5, i + 0.75, lab, ha="center", va="center", fontsize=8.6, color=col)
    ax.set_xlim(0, 2)
    ax.set_ylim(2, 0)
    ax.set_xticks([0.5, 1.5])
    ax.set_xticklabels(["reviewer: insecure", "reviewer: secure"], fontsize=9, color=t["ink"])
    ax.xaxis.tick_top()
    ax.set_yticks([0.5, 1.5])
    ax.set_yticklabels(["gate: FAIL", "gate: PASS"], fontsize=9, color=t["ink"])
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    prec, rec = tp / (tp + fp), tp / (tp + fn)
    pct = lambda x: f"{int(x * 100 + 0.5)}%"  # round half up (5/8 -> 63%)
    for k, (big, small) in enumerate([(pct(prec), f"precision  ({tp}/{tp + fp})"), (pct(rec), f"recall  ({tp}/{tp + fn})")]):
        fig.text(0.69, 0.56 - k * 0.24, big, fontsize=22, fontweight="bold", color=t["ink"])
        fig.text(0.69, 0.5 - k * 0.24, small, fontsize=9, color=t["ink2"])
    footer(fig, t, "Misses: two signature-binding flaws (unprobed API) and one key that leaves the module. "
           "The false alarm is a known suite-naming bug.")
    save(fig, "confusion", mode)


def repair(t, mode, rep):
    n = sum(r["condition"] == "gate" for r in rep)
    vals = [sum(r["fixed"] == "True" for r in rep if r["condition"] == c) for c in ("tests", "gate")]
    fig = new_fig(t, 10, 3.4)
    header(fig, t, "Repair", "Can the model fix its own insecure code?",
           f"Same {n} insecure files, same models and seeds. All gate-guided fixes verified by hand; exact McNemar p = 0.002")
    ax = fig.add_axes([0.3, 0.12, 0.62, 0.52])
    style(ax, t)
    labels = ["Test feedback  (\"all tests passed\")", "Glass Armor feedback  (findings)"]
    ax.barh(labels[::-1], vals[::-1], color=[t["blue"], t["neutral"]], height=0.5, edgecolor=t["bg"], linewidth=2)
    for i, v in enumerate(vals[::-1]):
        ax.text(v + 0.3, i, f"{v} / {n} fixed", va="center", fontsize=10.5, color=t["ink"], fontweight="bold" if i == 0 else "normal")
    ax.set_xlim(0, n)
    ax.set_xticks([0, 10, 20, n])
    for lbl in ax.get_yticklabels():
        lbl.set_color(t["ink"])
    save(fig, "repair", mode)


def repair_by_check(t, mode, rep):
    checks = ["P1", "P2", "P3", "A1", "A2", "A5"]
    names = {"P1": "P1  raw KEM secret as key", "P2": "P2  classical code left", "P3": "P3  secret in output",
             "A1": "A1  fallback without liboqs", "A2": "A2  classical option accepted", "A5": "A5  signature binding"}
    stats = {}
    for c in checks:
        items = [r for r in rep if r["condition"] == "gate" and c in r["start_flags"].split("|")]
        stats[c] = (sum(r["fixed"] == "True" for r in items), len(items))
    fig = new_fig(t, 10, 4.2)
    header(fig, t, "Repair, by finding", "Which findings the model could act on (gate-feedback condition)",
           "Bars: items fixed / items whose starting verdict included the check. Test feedback fixed 0 in every row")
    ax = fig.add_axes([0.3, 0.1, 0.62, 0.62])
    style(ax, t)
    ys = list(range(len(checks)))[::-1]
    for y, c in zip(ys, checks):
        f, n = stats[c]
        ax.barh(y, n, color=t["empty"] if mode == "light" else t["base"], height=0.56)
        ax.barh(y, f, color=t["blue"], height=0.56)
        ax.text(n + 0.2, y, f"{f}/{n}", va="center", fontsize=10, color=t["ink"])
    ax.set_yticks(ys)
    ax.set_yticklabels([names[c] for c in checks], fontsize=9.5, color=t["ink"])
    ax.set_xlim(0, max(n for _, n in stats.values()) * 1.15)
    save(fig, "repair-by-check", mode)


def code_card(t, mode):
    ex = ROOT / "paper_dossier" / "code_examples" / "real_output_fails_gate_and_repair"
    before = (ex / "gptoss_task06_s0_original_output.py").read_text(encoding="utf-8").splitlines()
    after = (ex / "gptoss_task06_s0_after_gate_repair.py").read_text(encoding="utf-8").splitlines()
    left = [(n, before[n - 1]) if n else (0, "") for n in (44, 45, 46, 0, 49, 50)]  # lines 43/48: comments with emoji
    right = [(n, after[n - 1]) for n in (37, 41, 47, 0, 63, 64, 68)]
    fig = new_fig(t, 12, 4.6)
    header(fig, t, "A real example", "gpt-oss-120b, task 06 (sealed secrets): passes all 10 tests, fails the gate, then fixed",
           "Verbatim excerpts. Highlighted lines are the ones the gate reported and the ones the model changed")
    panels = [(0.03, "Model output   |   tests 10/10   |   gate: FAIL (P1, lines 50 and 81)", left, {46, 50}, t["orange"]),
              (0.515, "After one round of gate feedback   |   tests 10/10   |   gate: PASS", right, {37, 64}, t["blue"])]
    for x0, title, lines, hl, accent in panels:
        ax = fig.add_axes([x0, 0.08, 0.455, 0.66])
        ax.set_xlim(0, 1)
        ax.set_ylim(len(lines) + 1.4, 0)
        ax.axis("off")
        ax.add_patch(FancyBboxPatch((0, 0), 1, len(lines) + 1.3, boxstyle="round,pad=0,rounding_size=0.02",
                                    facecolor=t["code"], edgecolor=t["base"], linewidth=1, mutation_aspect=8))
        ax.text(0.025, 0.75, title, fontsize=8.6, fontweight="bold", color=accent, va="center")
        for k, (num, src) in enumerate(lines):
            y = k + 1.75
            if num in hl:
                ax.add_patch(Rectangle((0.005, y - 0.45), 0.99, 0.9, color=accent, alpha=0.16))
            src = src.replace("‑", "-").rstrip()
            if num == 0:
                ax.text(0.09, y, "...", fontsize=8.6, color=t["muted"], va="center", family="monospace")
                continue
            ax.text(0.025, y, f"{num:>3}", fontsize=8.2, color=t["muted"], va="center", family="monospace")
            ax.text(0.09, y, src[:62] + (" ..." if len(src) > 62 else ""), fontsize=8.4, color=t["ink"],
                    va="center", family="monospace")
    save(fig, "code-example", mode)


def main():
    gf, counts, ev, rep, labels, key = load()
    for mode, t in THEMES.items():
        hero(t, mode, gf, ev, rep)
        architecture(t, mode)
        taxonomy(t, mode, counts)
        detection_heatmap(t, mode, gf)
        funnel(t, mode, ev)
        per_model(t, mode, ev)
        task_heatmap(t, mode, ev)
        confusion(t, mode, labels, key, ev)
        repair(t, mode, rep)
        repair_by_check(t, mode, rep)
        code_card(t, mode)
    print("wrote", len(list(OUT.glob("*.png"))), "images")


if __name__ == "__main__":
    main()
