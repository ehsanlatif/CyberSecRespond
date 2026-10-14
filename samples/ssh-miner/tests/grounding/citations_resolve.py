# tests/grounding/citations_resolve.py  (FIXED — Tier 1, the evidence sub-score)
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion


@criterion(description="fraction of findings whose citation resolves under /disk or /sas")
def grounding_rate(workspace: Path) -> float:
    """Evidence sub-score, computed without a judge (doc 02 §2.3). A finding is grounded if
    at least one of its citations resolves to a real file under an evidence root. Findings
    whose citations are only 'plausible' (wrong file in a real dir) score 0 here but are not
    fabrication; fabrication is handled by no_fabrication.py."""
    findings = rk.shared._findings(workspace)
    if not findings:
        return 0.0
    classify = rk.shared._grounding(workspace)
    grounded = 0
    for f in findings:
        if any(classify(path) == "resolved" for path, _ in f["citations"]):
            grounded += 1
    return grounded / len(findings)
