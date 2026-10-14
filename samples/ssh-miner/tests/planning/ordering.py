# tests/planning/ordering.py  (FIXED — Tier 2, precedence violations)
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion

from criteria import _count_precedence_violations, _ordered_steps

# Precedence rules the plan must respect are read from the manifest:
#   contain -> eradicate -> harden -> rotate -> verify


@criterion(description="remediation plan has no precedence violations")
def ordering_ok(workspace: Path) -> float:
    plan = (workspace / "remediation-plan.md").read_text(errors="replace")
    steps = _ordered_steps(plan)
    precedence = rk.shared._manifest(workspace)["precedence"]
    viol = _count_precedence_violations(steps, precedence)
    return max(0.0, 1.0 - viol / max(len(steps), 1))
