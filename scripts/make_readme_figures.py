"""Draw the README figures (light + dark PNG) from the project's recorded results.

Numbers come from results/tables (see paper_dossier/numbers.csv for sources):
  benchmark detection: gate_by_flaw.csv      Phase 3 funnel: phase3_eval_strict.csv
  repair: repair_items.csv
Palette: validated reference palette (dataviz skill), checked for CVD and contrast.
Usage: python scripts/make_readme_figures.py
"""
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "images"
T = ROOT / "results" / "tables"

THEMES = {
    "light": dict(bg="#fcfcfb", ink="#0b0b0b", ink2="#52514e", muted="#898781", grid="#e1e0d9", base="#c3c2b7",
                  blue="#2a78d6", orange="#eb6834", neutral="#c3c2b7",
                  ramp=["#86b6ef", "#5598e7", "#2a78d6", "#1c5cab"], box="#f0efec"),
    "dark": dict(bg="#1a1a19", ink="#f0efec", ink2="#c3c2b7", muted="#898781", grid="#2c2c2a", base="#383835",
                 blue="#3987e5", orange="#d95926", neutral="#5a5955",
                 ramp=["#184f95", "#256abf", "#3987e5", "#6da7ec"], box="#262624"),
}


def read(name):
    return list(csv.DictReader(open(T / name, encoding="utf-8")))


def data():
    gf = {r["flaw"]: r for r in read("gate_by_flaw.csv")}["all"]
    ev = read("phase3_eval_strict.csv")
    passing = [r for r in ev if r["all_tests_pass"] == "True"]
    pop = [r for r in passing if r["uses_oqs"] == "True"]
    corrected = [r for r in pop if r["gate_verdict"] == "FAIL" and not (
        r["model"] == "openai/gpt-oss-120b" and r["task"] == "task_20_suite_negotiation" and r["gate_flags"] == "A2")]
    rep = read("repair_items.csv")
    return {
        "detect": [("Functional tests", int(gf["tests"])), ("Semgrep (default rules)", int(gf["semgrep"])),
                   ("Bandit", int(gf["bandit"])), ("Glass Armor", int(gf["gate"]))],
        "n_variants": int(gf["variants"]),
        "funnel": [("AI migrations generated", len(ev)), ("Pass every functional test", len(passing)),
                   ("…and actually use liboqs", len(pop)), ("…flagged insecure by Glass Armor", len(corrected))],
        "repair": [("Test feedback\n(\"all tests passed\")", sum(r["fixed"] == "True" for r in rep if r["condition"] == "tests")),
                   ("Glass Armor feedback\n(specific findings)", sum(r["fixed"] == "True" for r in rep if r["condition"] == "gate"))],
        "n_repair": sum(r["condition"] == "gate" for r in rep),
    }


def style(ax, t):
    ax.set_facecolor(t["bg"])
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(t["base"])
    ax.tick_params(colors=t["ink2"], length=0, labelsize=11)
    ax.xaxis.grid(True, color=t["grid"], linewidth=0.8)
    ax.set_axisbelow(True)


def title(fig, t, main, sub):
    fig.text(0.02, 0.95, main, fontsize=15, fontweight="bold", color=t["ink"], va="top")
    fig.text(0.02, 0.86, sub, fontsize=10.5, color=t["ink2"], va="top")


def save(fig, name, mode):
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"{name}-{mode}.png", dpi=200, facecolor=fig.get_facecolor())
    plt.close(fig)


def detection(d, t, mode):
    fig, ax = plt.subplots(figsize=(8.4, 3.4), facecolor=t["bg"])
    fig.subplots_adjust(left=0.27, right=0.93, top=0.74, bottom=0.12)
    style(ax, t)
    labels = [n for n, _ in d["detect"]][::-1]
    vals = [v for _, v in d["detect"]][::-1]
    colors = [t["blue"] if n == "Glass Armor" else t["neutral"] for n in labels]
    ax.barh(labels, vals, color=colors, height=0.56, edgecolor=t["bg"], linewidth=2)
    n = d["n_variants"]
    for i, v in enumerate(vals):
        ax.text(v + 1, i, f"{v} / {n}", va="center", fontsize=11, color=t["ink"], fontweight="bold" if labels[i] == "Glass Armor" else "normal")
    ax.set_xlim(0, n * 1.12)
    ax.set_xticks([0, 20, 40, 60, n])
    for lbl in ax.get_yticklabels():
        lbl.set_color(t["ink"] if lbl.get_text() == "Glass Armor" else t["ink2"])
    title(fig, t, "Hidden flaws caught on the benchmark",
          f"{n} broken migrations that pass 100% of their tests · 0 false alarms on 20 correct ones (in-sample)")
    save(fig, "benchmark-detection", mode)


def funnel(d, t, mode):
    fig, ax = plt.subplots(figsize=(8.4, 3.6), facecolor=t["bg"])
    fig.subplots_adjust(left=0.38, right=0.94, top=0.76, bottom=0.12)
    style(ax, t)
    labels = [n for n, _ in d["funnel"]][::-1]
    vals = [v for _, v in d["funnel"]][::-1]
    colors = [t["orange"], t["blue"], t["blue"], t["blue"]]
    ax.barh(labels, vals, color=colors, height=0.56, edgecolor=t["bg"], linewidth=2)
    for i, v in enumerate(vals):
        ax.text(v + 5, i, str(v), va="center", fontsize=11, color=t["ink"], fontweight="bold" if i == 0 else "normal")
    ax.set_xlim(0, max(vals) * 1.12)
    for lbl in ax.get_yticklabels():
        lbl.set_color(t["ink"])
    title(fig, t, "400 real AI migrations (4 models × 20 tasks × 5 samples)",
          f"Glass Armor flags {vals[0]} of the {vals[1]} working PQC migrations; Semgrep flagged 0 of them, Bandit 1")
    save(fig, "migration-funnel", mode)


def repair(d, t, mode):
    fig, ax = plt.subplots(figsize=(8.4, 2.9), facecolor=t["bg"])
    fig.subplots_adjust(left=0.27, right=0.93, top=0.7, bottom=0.14)
    style(ax, t)
    labels = [n for n, _ in d["repair"]]
    vals = [v for _, v in d["repair"]]
    n = d["n_repair"]
    ax.barh(labels[::-1], vals[::-1], color=[t["blue"], t["neutral"]], height=0.5, edgecolor=t["bg"], linewidth=2)
    for i, v in enumerate(vals[::-1]):
        ax.text(v + 0.3, i, f"{v} / {n} fixed", va="center", fontsize=11, color=t["ink"], fontweight="bold" if i == 0 else "normal")
    ax.set_xlim(0, n * 1.0)
    ax.set_xticks([0, 10, 20, n])
    for lbl in ax.get_yticklabels():
        lbl.set_color(t["ink"])
    title(fig, t, "Can the AI fix its own insecure code?",
          "Same 31 insecure files, same models — all 10 gate-guided fixes verified as genuine")
    save(fig, "repair", mode)


def architecture(t, mode):
    fig, ax = plt.subplots(figsize=(11, 3.8), facecolor=t["bg"])
    fig.subplots_adjust(left=0.01, right=0.99, top=0.98, bottom=0.02)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 36)
    ax.axis("off")

    def box(x, y, w, h, head, sub, accent=None):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.6",
                                    facecolor=t["box"], edgecolor=accent or t["base"], linewidth=2 if accent else 1.2))
        ax.text(x + w / 2, y + h * 0.66, head, ha="center", va="center", fontsize=10.5, fontweight="bold", color=t["ink"])
        ax.text(x + w / 2, y + h * 0.3, sub, ha="center", va="center", fontsize=9, color=t["ink2"], linespacing=1.3)

    def arrow(x1, y1, x2, y2, color=None, text=None):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=14, linewidth=1.6,
                                     color=color or t["muted"]))
        if text:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 1.6, text, ha="center", fontsize=8.5, color=t["ink2"])

    box(1, 19, 16, 12, "Classical code", "RSA · ECDSA · X25519")
    box(21, 19, 16, 12, "LLM migration", "gemma · qwen · gpt-oss")
    box(41, 19, 16, 12, "Functional tests", "all green ✓ (but blind)")
    box(61, 16, 21, 18, "Glass Armor gate", "static rules + dataflow (P1–P6)\nbehavioural attacks (A1–A6)", accent=t["blue"])
    box(87, 26, 12, 7.5, "PASS", "ship it")
    box(87, 14, 12, 7.5, "FAIL", "+ findings", accent=t["orange"])
    arrow(17.6, 25, 20.4, 25)
    arrow(37.6, 25, 40.4, 25)
    arrow(57.6, 25, 60.4, 25)
    arrow(82.6, 28.5, 86.4, 29.5)
    arrow(82.6, 21.5, 86.4, 18, color=t["orange"])
    ax.add_patch(FancyArrowPatch((93, 13.2), (29, 18.4), connectionstyle="arc3,rad=-0.22", arrowstyle="-|>",
                                 mutation_scale=14, linewidth=1.6, color=t["orange"]))
    ax.text(29, 6.5, "repair loop: findings are fed back to the model", ha="left", fontsize=9.5, color=t["ink2"])
    save(fig, "architecture", mode)


def main():
    d = data()
    for mode, t in THEMES.items():
        detection(d, t, mode)
        funnel(d, t, mode)
        repair(d, t, mode)
        architecture(t, mode)
    print("wrote", sorted(p.name for p in OUT.glob("*.png")))


if __name__ == "__main__":
    main()
