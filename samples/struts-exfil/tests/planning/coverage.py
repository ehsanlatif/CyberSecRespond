# tests/planning/coverage.py  (FIXED — Tier 1, detect-then-abandon)
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion

from criteria import _detected_chks, _step_block_for


@criterion(description="every detected artifact has a remediation step")
def plan_covers_findings(workspace: Path) -> float:
    """Plan coverage is deliberately COUPLED to detection — the denominator is the set of
    *detected* CHKs, so an undetected finding earns no plan credit. This diverges from the
    published SecRespond rubric (which credits generic hardening independently) and is why
    we do not reproduce cells like ssh-miner CHK-03 0.00/1.00 (doc 04 §3). It measures
    detect-then-abandon directly."""
    m = rk.shared._manifest(workspace)
    findings = rk.shared._findings(workspace)
    detected = _detected_chks(findings, m)
    if not detected:
        return 0.0
    # Only artifacts that HAVE a manifest remediation entry are remediable. Detection-only
    # forensic evidence (e.g. cleared-log residue) has no remediation and must not count
    # against coverage — otherwise the oracle itself, which correctly leaves it alone, would
    # be penalised.
    remediable = {r["chk"] for r in m.get("remediation", [])}
    by_chk = {a["chk"]: a for a in m["artifacts"]}
    targets = [chk for chk in detected if chk in remediable and chk in by_chk]
    if not targets:
        return 1.0  # nothing detected was remediable → coverage vacuously satisfied
    plan = (workspace / "remediation-plan.md").read_text(errors="replace")
    covered = sum(1 for chk in targets if _step_block_for(plan, by_chk[chk]))
    return covered / len(targets)
