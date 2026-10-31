"""Assemble paper_dossier/DOSSIER.md from scripts/dossier/DOSSIER_template.md.

Directives in the template (each on its own line or inline for <<num>>):
  <<include path>>   paste the file verbatim in a fenced block
  <<table path>>     render a CSV as a Markdown table
  <<num id>>         value from paper_dossier/numbers.csv plus its [source: ..., script: ...]
Usage: python scripts/dossier/build_dossier.py
"""
import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NUMS = {r["id"]: r for r in csv.DictReader(open(ROOT / "paper_dossier" / "numbers.csv", encoding="utf-8"))}
LANG = {".py": "python", ".yaml": "yaml", ".yml": "yaml", ".txt": "text", ".md": "markdown", ".diff": "diff", ".csv": "text"}


def include(path):
    p = ROOT / path
    text = p.read_text(encoding="utf-8").rstrip("\n")
    fence = "````" if "```" in text else "```"
    return f"*Verbatim: `{path}`*\n\n{fence}{LANG.get(p.suffix, '')}\n{text}\n{fence}"


def table(path):
    rows = list(csv.reader(open(ROOT / path, encoding="utf-8")))
    cell = lambda c: c.replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(cell(c) for c in rows[0]) + " |", "|" + "---|" * len(rows[0])]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows[1:]]
    return f"*Source: `{path}`*\n\n" + "\n".join(out)


def num(m):
    n = NUMS.get(m.group(1))
    if not n:
        return f"**UNVERIFIED (no number id `{m.group(1)}`)**"
    return f"{n['value']} [source: {n['source']}, script: {n['script']}]"


def main():
    tpl = (ROOT / "scripts" / "dossier" / "DOSSIER_template.md").read_text(encoding="utf-8")
    out = []
    for line in tpl.splitlines():
        s = line.strip()
        if s.startswith("<<include ") and s.endswith(">>"):
            out.append(include(s[10:-2].strip()))
        elif s.startswith("<<table ") and s.endswith(">>"):
            out.append(table(s[8:-2].strip()))
        else:
            out.append(re.sub(r"<<num ([\w.:/\-]+)>>", num, line))
    text = "\n".join(out) + "\n"
    (ROOT / "paper_dossier" / "DOSSIER.md").write_text(text, encoding="utf-8")
    missing = re.findall(r"UNVERIFIED \(no number id `([^`]+)`", text)
    print(f"wrote paper_dossier/DOSSIER.md ({len(text.splitlines())} lines); missing number ids: {missing or 'none'}")


if __name__ == "__main__":
    main()
