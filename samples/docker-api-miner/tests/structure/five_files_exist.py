# tests/structure/five_files_exist.py  (FIXED — structure gate, required_pass)
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion

REQUIRED = ("progress.md", "intrusion-report.md", "vuln-report.md",
            "baseline-report.md", "remediation-plan.md")


@criterion(description="all five required report files exist", required_pass=True)
def five_files_exist(workspace: Path) -> bool:
    # A run that produces fewer than five files is `incomplete_output`, not a low score
    # (doc 04 §2.2). The structure gate is multiplicative in the reward (doc 02 §4.4).
    return all((workspace / name).exists() for name in REQUIRED)
