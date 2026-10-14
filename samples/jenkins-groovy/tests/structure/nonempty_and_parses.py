# tests/structure/nonempty_and_parses.py  (FIXED — structure gate, required_pass)
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion

from criteria import REPORT_FILES

REQUIRED = ("progress.md", "intrusion-report.md", "vuln-report.md",
            "baseline-report.md", "remediation-plan.md")
MIN_CHARS = 40  # a plausible report has at least a heading and a sentence


@criterion(description="every report is non-empty and has at least one markdown heading",
           required_pass=True)
def nonempty_and_parses(workspace: Path) -> bool:
    for name in REQUIRED:
        p = workspace / name
        if not p.exists():
            return False
        text = p.read_text(errors="replace").strip()
        if len(text) < MIN_CHARS:
            return False
        if not any(line.lstrip().startswith("#") for line in text.splitlines()):
            return False
    return True
