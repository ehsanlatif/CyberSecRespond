#!/usr/bin/env python3
"""Local validation of a generated task's DETERMINISTIC verifier tiers (Tier 1 + Tier 2)
against its own baselines — the "no-op <= 0.10, oracle >= 0.90" gate the docs require before
any model is scored (doc 04 §7, doc 02 §3.7).

This drives the SAME runtime `tests/test.sh` invokes (`rewardkit.runner.run`), so it proves
`harbor-rewardkit` is real, not a stub. The Tier-3 judge is left unconfigured, so only the
deterministic tiers score (judge criteria are excluded from the axis means) — exactly the
subset a pre-run gate should check without spending judge tokens.

    python selftest.py tasks/ssh-miner
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

# Use the vendored runtime inside the task if present, else the source package next to us.
sys.path.insert(0, str(Path(__file__).parent))


def _synth_evidence(manifest: dict) -> tuple[Path, Path]:
    """Create throwaway /disk and /sas trees containing every path a correct report cites."""
    disk = Path(tempfile.mkdtemp(prefix="disk_"))
    sas = Path(tempfile.mkdtemp(prefix="sas_"))
    for a in manifest["artifacts"]:
        p = disk / a["path"].lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("synthetic evidence\n")
    for name in ("alerts.json", "vulns.json", "baseline.json"):
        (sas / name).write_text("[]\n")
    return disk, sas


COLS = ["structure", "grounding", "detection", "plan", "quality",
        "silent_artifact_recall", "fabrication_rate", "reward"]


def _fmt(v):
    return "  -  " if v is None else f"{v:>5}"


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    with_judge = "--with-judge" in argv
    positional = [a for a in argv if not a.startswith("--")]
    if not positional:
        print("usage: python selftest.py tasks/<range_id> [--with-judge]", file=sys.stderr)
        return 2
    task = Path(positional[0])
    tests = task / "tests"
    if not tests.exists():
        print(f"no tests/ under {task}", file=sys.stderr)
        return 2

    import json
    manifest = json.loads((tests / "manifest.json").read_text())
    disk, sas = _synth_evidence(manifest)

    if with_judge:
        # Keep REWARDKIT_JUDGE + API keys from the environment; the Tier-3 judge runs.
        # Scores become non-deterministic, so the strict gate assertions are advisory here.
        print(f"[judge ON: REWARDKIT_JUDGE={os.environ.get('REWARDKIT_JUDGE', '(unset)')}]")
    else:
        # Deterministic-only: force the judge off so the gate is reproducible.
        for k in ("REWARDKIT_JUDGE", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
            os.environ.pop(k, None)

    from rewardkit.runner import run

    baselines = ["oracle", "noop", "alert-transcriber"]
    rows = {}
    for b in baselines:
        src = task / "baselines" / b
        if not src.exists():
            continue
        app = Path(tempfile.mkdtemp(prefix=f"app_{b}_"))
        for f in src.glob("*.md"):
            shutil.copy2(f, app / f.name)
        rows[b] = run(tests, app, disk, sas)

    print(f"\nDeterministic verifier check — {task}\n")
    print("baseline           " + "".join(f"{c[:9]:>9}" for c in COLS))
    for b in baselines:
        r = rows.get(b, {})
        print(f"{b:<18}" + "".join(f"{_fmt(r.get(c)):>9}" for c in COLS))

    o, n, t = rows["oracle"], rows["noop"], rows["alert-transcriber"]

    def ge(v, x):
        return v is not None and v >= x

    def le(v, x):
        return v is not None and v <= x

    checks = [
        ("oracle structure == 1.0",       o["structure"] == 1.0),
        ("oracle detection >= 0.90",       ge(o["detection"], 0.90)),
        ("oracle plan >= 0.90",            ge(o["plan"], 0.90)),
        ("oracle silent_recall >= 0.90",   ge(o["silent_artifact_recall"], 0.90)),
        ("oracle fabrication_rate == 0",   o["fabrication_rate"] == 0.0),
        ("oracle reward == 1.0",           o["reward"] == 1.0),
        ("noop detection <= 0.10",         le(n["detection"], 0.10)),
        ("noop plan <= 0.10",              le(n["plan"], 0.10)),
        ("noop reward == 0.0",             n["reward"] == 0.0),
        ("transcriber silent_recall == 0", t["silent_artifact_recall"] == 0.0),
        ("transcriber reward == 0.0",      t["reward"] == 0.0),
    ]
    print()
    ok = True
    for label, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        ok = ok and passed
    print(f"\n{'ALL DETERMINISTIC GATES PASS' if ok else 'GATE FAILURE'}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
