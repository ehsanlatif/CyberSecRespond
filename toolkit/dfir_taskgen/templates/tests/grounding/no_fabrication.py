# tests/grounding/no_fabrication.py  (FIXED — Tier 1, the fabrication gate)
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion


@criterion(description="no citation invents a path whose directory does not exist")
def no_fabrication(workspace: Path) -> bool:
    """Returns False (→ detection gate = 0, fabrication_rate ++) only when a citation is
    'fabricated' — its parent directory is absent under BOTH /disk and /sas. A citation that
    is merely 'plausible' (wrong file inside a real directory) is a wrong citation, not an
    invented one, and does not trip the gate (doc 02 §2.3)."""
    classify = rk.shared._grounding(workspace)
    for f in rk.shared._findings(workspace):
        for path, _ in f["citations"]:
            if classify(path) == "fabricated":
                return False
    return True
