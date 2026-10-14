"""Blueprint = the declarative input dimensions of a range (doc 03 §4.1).

A blueprint is the single authored input. From it the generator emits the manifest, the
task package, the verifier bindings, and the baselines — with no other range-specific code
(doc 02 §3.0, doc 03 §4). Blueprints are JSON by default; YAML is accepted transparently
when PyYAML is installed.
"""
from __future__ import annotations

import json
from pathlib import Path

# The five capability dimensions (doc 01 §5.3 / doc 03 §3.1).
CAP_DIMENSIONS = ("ENT", "PER", "BAS", "VUL", "Q")

# Canonical remediation precedence for the subdomain.
DEFAULT_PRECEDENCE = ["contain", "eradicate", "harden", "rotate", "verify"]

REQUIRED_TOP = ("range_id", "platform", "difficulty", "chain", "artifacts")
REQUIRED_ARTIFACT = ("chk", "path", "kind", "capability", "alerted")
REQUIRED_CHAIN = ("step", "attck", "desc")


class BlueprintError(ValueError):
    """Raised when a blueprint is malformed — fail loudly before emitting a broken task."""


def load(path: str | Path) -> dict:
    path = Path(path)
    text = path.read_text()
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # optional dependency
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise BlueprintError(
                f"{path} is YAML but PyYAML is not installed. Install pyyaml, or convert the "
                f"blueprint to JSON."
            ) from exc
        bp = yaml.safe_load(text)
    else:
        bp = json.loads(text)
    if not isinstance(bp, dict):
        raise BlueprintError(f"{path}: top level must be an object/mapping")
    return normalize(validate(bp))


def validate(bp: dict) -> dict:
    for key in REQUIRED_TOP:
        if key not in bp:
            raise BlueprintError(f"missing required top-level key: {key!r}")

    if not isinstance(bp["platform"], dict) or "os" not in bp["platform"]:
        raise BlueprintError("platform must be an object with at least an 'os' key")

    if not isinstance(bp["difficulty"], int) or not 1 <= bp["difficulty"] <= 4:
        raise BlueprintError("difficulty must be an integer 1..4 (L1..L4)")

    if not bp["chain"]:
        raise BlueprintError("chain must be a non-empty list")
    steps = set()
    for c in bp["chain"]:
        for k in REQUIRED_CHAIN:
            if k not in c:
                raise BlueprintError(f"chain step missing {k!r}: {c}")
        steps.add(c["step"])
        for dep in c.get("depends_on", []) or []:
            if dep not in {s["step"] for s in bp["chain"]}:
                raise BlueprintError(f"chain step {c['step']} depends_on unknown step {dep}")

    if not bp["artifacts"]:
        raise BlueprintError("artifacts must be a non-empty list")
    chks = []
    for a in bp["artifacts"]:
        for k in REQUIRED_ARTIFACT:
            if k not in a:
                raise BlueprintError(f"artifact missing {k!r}: {a}")
        cap = a["capability"].split("-", 1)[0]
        if cap not in CAP_DIMENSIONS:
            raise BlueprintError(
                f"artifact {a['chk']} capability {a['capability']!r} is not one of "
                f"{CAP_DIMENSIONS}"
            )
        chks.append(a["chk"])
    if len(chks) != len(set(chks)):
        dupes = sorted({c for c in chks if chks.count(c) > 1})
        raise BlueprintError(f"duplicate artifact CHK ids: {dupes}")

    # Remediation must key on real CHKs (either an artifact or a response checkpoint) and
    # use only phases that appear in the precedence list.
    precedence = bp.get("precedence", DEFAULT_PRECEDENCE)
    for r in bp.get("remediation", []):
        if "chk" not in r or "action" not in r:
            raise BlueprintError(f"remediation entry needs 'chk' and 'action': {r}")
        phase = r.get("phase")
        if phase and phase not in precedence:
            raise BlueprintError(
                f"remediation {r['chk']} phase {phase!r} not in precedence {precedence}"
            )

    if bp.get("no_cve_entry") is False and not any(
        a["capability"].startswith("VUL") for a in bp["artifacts"]
    ):
        # Not fatal, but a CVE-entry range with no VUL artifact is almost certainly a mistake.
        raise BlueprintError(
            "no_cve_entry is false but no VUL-capability artifact describes the CVE entry"
        )
    return bp


def normalize(bp: dict) -> dict:
    """Fill defaults so downstream emitters never branch on absence."""
    bp.setdefault("title", bp["range_id"])
    bp.setdefault(
        "description",
        f"Post-compromise forensic investigation and remediation planning on "
        f"{bp['platform']['os']} {bp['platform'].get('version', '')}".strip(),
    )
    bp.setdefault("tags", ["security", "dfir", "incident-response", "long-horizon"])
    bp.setdefault("difficulty_label", {1: "easy", 2: "medium", 3: "hard", 4: "hard"}[bp["difficulty"]])
    bp.setdefault("alert_coverage", _measured_alert_coverage(bp))
    bp.setdefault("no_cve_entry", not any(a["capability"].startswith("VUL") for a in bp["artifacts"]))
    bp.setdefault("precedence", list(DEFAULT_PRECEDENCE))
    bp.setdefault("decoys", [])
    bp.setdefault("remediation", [])
    bp.setdefault("timeouts", {"agent_sec": 3600, "verifier_sec": 900})
    bp.setdefault("judge", {"attribution": True, "quality": True})
    bp.setdefault(
        "scenario",
        f"A {bp['platform']['os']} host has been compromised. A read-only forensic image and "
        f"the security product's output are provided; reconstruct what happened and produce a "
        f"verified remediation plan.",
    )
    return bp


def _measured_alert_coverage(bp: dict) -> float:
    """If not stated, derive coverage from the artifacts' alerted flags (doc 03 §3.2 — it is
    a measured per-range value, not a grid bucket)."""
    arts = bp["artifacts"]
    if not arts:
        return 0.0
    return round(sum(1 for a in arts if a.get("alerted")) / len(arts), 2)
