# tests/detection/chain_topology.py  (FIXED — Tier 2, graph-edit distance)
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion

from criteria import _dag, _ged, _parse_chain


@criterion(description="attack chain topology matches ground truth")
def chain_score(workspace: Path) -> float:
    """Attack-chain reconstruction is a structure problem: parse the agent's chain into a
    DAG and compare topologically. Normalised graph edit distance over (node set, edge set)
    — the denominator is nodes + edges, and node deletions carry their incident edges, so
    the score degrades smoothly with missing/extra steps (doc 02 §3.4)."""
    gt = _dag(rk.shared._manifest(workspace)["chain"])
    pred = _parse_chain(workspace / "intrusion-report.md")
    denom = len(gt["nodes"]) + len(gt["edges"])
    if denom == 0:
        return 1.0
    return max(0.0, 1.0 - _ged(pred, gt) / denom)
