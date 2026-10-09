"""Print one version's section of CHANGELOG.md - paste it as the GitHub Release notes for that tag.

    python tools/release_notes.py 1.11.0          (or: python tools/release_notes.py   -> the newest version)
"""
import re
import sys
from pathlib import Path

text = (Path(__file__).resolve().parent.parent / "CHANGELOG.md").read_text(encoding="utf-8")
heads = list(re.finditer(r"^## (\d+\.\d+\.\d+) - (\S+)", text, re.M))
if not heads:
    sys.exit("No versions found in CHANGELOG.md")
want = sys.argv[1].lstrip("v") if len(sys.argv) > 1 else heads[0].group(1)
for i, h in enumerate(heads):
    if h.group(1) == want:
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        print(text[h.end():end].strip())
        break
else:
    sys.exit(f"Version {want} isn't in CHANGELOG.md")
