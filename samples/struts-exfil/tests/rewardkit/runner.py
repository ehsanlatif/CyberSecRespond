"""The scoring loop: import criterion files, evaluate instances, apply gates, aggregate.

Directory → reward-key mapping mirrors the design (doc 02 §2.1, §3.6):
  structure/  → structure gate (required_pass, multiplicative)
  grounding/  → grounding rate + fabrication gate
  detection/  → `detection` axis (discovery, silent_recall[w=0], chain, no_cve, attribution)
  planning/   → `plan` axis (coverage, verification, ordering, plan-quality judge)
  quality/    → `quality` key (Q-dimension judge; eval-only by default)
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import rewardkit as rk
import rewardkit.judge as judgemod   # dotted form: the module __getattr__ registrar shadows
                                     # `from rewardkit import judge` (it returns a function)

GROUPS = ["structure", "grounding", "detection", "planning", "quality"]
GROUP_TO_REWARD = {"planning": "plan"}          # others map to their own name
LATE = ("discovery.py", "verification.py")      # generated instance-registration files
THRESHOLD = 0.70                                # per-axis pass threshold (doc 01 §4.6)


def _reward_key(group: str) -> str:
    return GROUP_TO_REWARD.get(group, group)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _wmean(pairs):
    num = sum(w * s for w, s in pairs)
    den = sum(w for w, _ in pairs)
    return round(num / den, 4) if den else None


def _parse_reward_toml(path: Path) -> list:
    """Tiny purpose-built parser for reward.toml ([[reward]] name/aggregation) — avoids a TOML
    dependency so the deterministic path runs on stock Python 3.9."""
    blocks, cur = [], None
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line == "[[reward]]":
            cur = {}
            blocks.append(cur)
        elif cur is not None and "=" in line:
            k, _, v = line.partition("=")
            cur[k.strip()] = v.strip().strip('"')
    return blocks


def run(tests, app, disk, sas) -> dict:
    tests, app = Path(tests), Path(app)
    os.environ.update(RK_TESTS=str(tests), RK_DISK=str(disk),
                      RK_SAS=str(sas), RK_APP=str(app))
    if str(tests) not in sys.path:
        sys.path.insert(0, str(tests))

    rk._reset()
    _load(tests / "criteria.py", "criteria")
    import criteria as C  # now resolvable via sys.modules

    for group in GROUPS:
        gdir = tests / group
        if not gdir.exists():
            continue
        rk._set_group(group)
        files = sorted(gdir.glob("*.py"))
        for f in [x for x in files if x.name not in LATE] + [x for x in files if x.name in LATE]:
            _load(f, f"rk_{group}_{f.stem}")
    rk._set_group(None)

    details, group_pairs = [], {g: [] for g in GROUPS}
    required_fail, silent_recall = False, None

    # --- deterministic instances (Tier 1 + Tier 2) ---
    for (name, _args), inst in rk._instances.items():
        d = rk._defs.get(name)
        if d is None:
            continue
        try:
            val = d["fn"](app, *inst["args"], **inst["kwargs"])
            score = (1.0 if val else 0.0) if isinstance(val, bool) else float(val)
            err = None
        except Exception as e:
            score, err = 0.0, f"{type(e).__name__}: {e}"
        details.append({"group": inst["group"], "criterion": name, "args": list(inst["args"]),
                        "weight": inst["weight"], "score": score, "error": err})
        if name == "silent_artifact_recall":
            silent_recall = score
        if d.get("required_pass") and score < 1.0:
            required_fail = True
        if inst["weight"] > 0 and inst["group"] in group_pairs:
            group_pairs[inst["group"]].append((inst["weight"], score))

    # --- Tier 3 judge tomls ---
    for group in GROUPS:
        gdir = tests / group
        if not gdir.exists():
            continue
        for tf in sorted(gdir.glob("*.toml")):
            for r in judgemod.run_judge(tf, app, tests)["criteria"]:
                details.append({"group": group, "criterion": f"{tf.stem}:{r['name']}",
                                "args": [], "weight": r["weight"], "score": r["score"],
                                "skipped": r.get("skipped", False),
                                "judge_reason": r.get("reason")})
                if not r.get("skipped") and r["score"] is not None and r["weight"] > 0:
                    group_pairs[group].append((r["weight"], r["score"]))

    # --- aggregate into reward keys per reward.toml ---
    reward = {}
    for g in GROUPS:
        reward[_reward_key(g)] = _wmean(group_pairs[g])
    reward_spec = _parse_reward_toml(tests / "reward.toml") if (tests / "reward.toml").exists() else []

    # --- gates ---
    classify = C._grounding(app)
    cites = [c for f in C._findings(app) for c in f["citations"]]
    fabricated = sum(1 for path, _ in cites if classify(path) == "fabricated")
    fab_rate = round(fabricated / len(cites), 4) if cites else 0.0

    outcome = "incomplete_output" if required_fail else "scored"
    reward["structure"] = 0.0 if required_fail else 1.0
    # Preserve the pre-gate detection so a strong axis is never hidden by the fabrication gate.
    reward["detection_pre_gate"] = reward.get("detection")
    # Fabrication handling. Default ("gate") keeps doc 02 G4's hard-zero — the correct signal for
    # the GRPO training loop (never reward carpet-bombing). Set RK_FAB_MODE=graded for evaluation
    # reporting to apply a proportional penalty instead, so a 1-of-N bad citation does not erase
    # an otherwise-strong detection axis.
    if fab_rate > 0:
        if os.environ.get("RK_FAB_MODE", "gate") == "graded":
            _det = reward.get("detection") or 0.0
            reward["detection"] = round(max(0.0, _det * (1.0 - min(1.0, 5.0 * fab_rate))), 4)
        else:
            reward["detection"] = 0.0

    det = reward.get("detection") or 0.0
    plan = reward.get("plan") or 0.0
    passed = outcome == "scored" and det >= THRESHOLD and plan >= THRESHOLD
    reward["reward"] = 1.0 if passed else 0.0
    reward["silent_artifact_recall"] = silent_recall if silent_recall is not None else 0.0
    reward["fabrication_rate"] = fab_rate
    reward["outcome"] = outcome

    (app / "reward.json").write_text(json.dumps(reward, indent=2) + "\n")
    (app / "reward-details.json").write_text(json.dumps(details, indent=2) + "\n")
    return reward
