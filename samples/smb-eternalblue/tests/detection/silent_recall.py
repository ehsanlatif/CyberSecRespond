# tests/detection/silent_recall.py  (FIXED — Tier 1, the headline diagnostic)
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion

from criteria import _artifact_mentioned


@criterion(description="recall over non-alerted (silent) ground-truth artifacts")
def silent_artifact_recall(workspace: Path) -> float:
    """The cleanest single number for P1 (reactive tunnel vision). Recall restricted to the
    artifacts that were NOT surfaced as alerts, so it isolates proactive investigation from
    alert transcription (doc 01 §5.3). Registered with weight 0.0 in discovery.py — reported,
    not scored."""
    m = rk.shared._manifest(workspace)
    findings = rk.shared._findings(workspace)
    silent = [a for a in m["artifacts"] if not a.get("alerted", False)]
    if not silent:
        return 1.0
    found = sum(1 for a in silent if _artifact_mentioned(findings, a))
    return found / len(silent)
