"""Emit a complete Harbor task package from a validated blueprint.

Layout produced (mirrors doc 04 §4):

    tasks/<range_id>/
    ├── task.toml
    ├── Dockerfile
    ├── instruction.md
    ├── assets/{disk.tar.gz(+.sha256) | README}, sas-mock/{alerts,vulns,baseline}.json
    ├── tests/            (the fixed generic verifier + manifest + generated bindings)
    └── baselines/{oracle,noop,alert-transcriber}/  (5 reports each)
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

TEMPLATES = Path(__file__).parent / "templates"
REWARDKIT = Path(__file__).parent.parent / "rewardkit"   # vendored into each task's tests/

MANIFEST_KEYS = ("range_id", "difficulty", "alert_coverage", "platform", "chain",
                 "artifacts", "remediation", "precedence", "no_cve_entry", "decoys")


# ----------------------------------------------------------------------------- manifest

def manifest_dict(bp: dict) -> dict:
    m = {k: bp[k] for k in MANIFEST_KEYS if k in bp}
    m["signature"] = _signature(bp)
    return m


def _signature(bp: dict) -> str:
    """Reasoning signature (doc 03 §3.3): distinct problems, not surface variants."""
    persistence = sorted(
        a["capability"] for a in bp["artifacts"] if a["capability"].startswith("PER")
    )
    entry = next((c["attck"] for c in sorted(bp["chain"], key=lambda c: c["step"])), "")
    hops = max((len(c.get("depends_on", []) or []) and c["step"] for c in bp["chain"]), default=0)
    key = json.dumps(
        [entry, tuple(persistence), hops, bp.get("alert_coverage"),
         sorted(d.get("path", "") for d in bp.get("decoys", []))],
        sort_keys=True,
    )
    return hashlib.sha256(key.encode()).hexdigest()[:12]


# ----------------------------------------------------------------------------- helpers

def _by_cap(artifacts: list, prefix: str) -> list:
    return [a for a in artifacts if a["capability"].startswith(prefix)]


def _cite(a: dict) -> str:
    line = a.get("line")
    return f"`{a['path']}:{line}`" if line else f"`{a['path']}`"


def _chain_arrow(chain: list) -> str:
    """Compact 'spine → {branches}' rendering of the attack chain (doc 04 §7.2 form)."""
    steps = sorted(chain, key=lambda c: c["step"])
    by_step = {c["step"]: c for c in steps}
    dependents: dict[int, int] = {}
    for c in steps:
        for d in c.get("depends_on", []) or []:
            dependents[d] = dependents.get(d, 0) + 1
    if not dependents or max(dependents.values()) < 2:
        return " → ".join(c["attck"] for c in steps)  # linear chain
    hub = min(s for s, n in dependents.items() if n == max(dependents.values()))
    spine = [c["attck"] for c in steps if c["step"] <= hub]
    branches = [c["attck"] for c in steps if hub in (c.get("depends_on") or [])]
    return " → ".join(spine) + " → {" + ", ".join(branches) + "}"


def _chain_edges_md(chain: list) -> str:
    """Explicit one-edge-per-line rendering so the verifier's chain parser reconstructs the
    full topology exactly — the compact 'spine → {branches}' arrow is lossy for chains with
    more than one branch point."""
    steps = {c["step"]: c for c in chain}
    lines = []
    for c in sorted(chain, key=lambda c: c["step"]):
        deps = c.get("depends_on")
        if deps is None and c["step"] > 1 and (c["step"] - 1) in steps:
            deps = [c["step"] - 1]
        for d in deps or []:
            if d in steps:
                lines.append(f"- {steps[d]['attck']} → {c['attck']}")
    return "\n".join(lines) if lines else "\n".join(f"- {c['attck']}" for c in chain)


def _chain_prose(chain: list) -> str:
    steps = sorted(chain, key=lambda c: c["step"])
    parts = []
    for c in steps:
        dep = f" (after step {', '.join(map(str, c['depends_on']))})" if c.get("depends_on") else ""
        parts.append(f"step {c['step']} {c['attck']} — {c['desc']}{dep}")
    return "; ".join(parts)


# ----------------------------------------------------------------------------- writers

def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith("\n") else text + "\n")


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n")


def emit_task_toml(bp: dict, out: Path) -> None:
    """Harbor task.toml (schema 1.4). `[task].name` MUST be org/name; `authors` under [task].
    Verified against harbor 0.21 `TaskConfig.model_validate_toml`."""
    t = bp["timeouts"]
    tags = ", ".join(f'"{x}"' for x in bp["tags"])
    desc = bp["description"].replace('\\', ' ').replace('"', "'").replace("\n", " ")
    text = f'''schema_version = "1.4"

[task]
name        = "dfir-eval/{bp['range_id']}"
version     = "1.0.0"
description = "{desc}"
authors     = [{{ name = "DFIR Synthetic Corpus" }}]
keywords    = [{tags}]

[metadata]
author_name  = "DFIR Synthetic Corpus"
author_email = ""
difficulty   = "{bp['difficulty_label']}"
category     = "security"
tags         = [{tags}]

[agent]
timeout_sec = {float(t['agent_sec'])}

[verifier]
timeout_sec = {float(t['verifier_sec'])}

[verifier.env]
# Tier-3 LLM judge (OPTIONAL). ${{VAR:-}} = empty default, so a missing var does NOT block the
# run (Harbor would treat a bare ${{VAR}} as required) — the judge degrades to Tier 1+2. To
# enable it: export REWARDKIT_JUDGE=anthropic/claude-opus-5 and ANTHROPIC_API_KEY before running.
ANTHROPIC_API_KEY = "${{ANTHROPIC_API_KEY:-}}"
REWARDKIT_JUDGE   = "${{REWARDKIT_JUDGE:-}}"

[environment]
# Analysis machine is Linux regardless of the victim OS in the forensic image at /disk.
os                = "linux"
build_timeout_sec = 900.0
'''
    write_text(out / "task.toml", text)


def emit_dockerfile(bp: dict, out: Path) -> None:
    # Harbor builds this with environment/ AS THE BUILD CONTEXT, so every COPY source is
    # relative to environment/ (disk.tar.gz, sas-mock live there — placed by build_disk.py).
    text = '''FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \\
      file binutils grep ripgrep jq python3 python3-pip less tree \\
      gzip xxd poppler-utils ca-certificates \\
      tmux asciinema \\
    && rm -rf /var/lib/apt/lists/*
# binutils -> strings/strings -e l (binary blobs, registry hives, .evtx); gzip -> zcat rotated
# logs; xxd -> hexdump; poppler-utils -> pdftotext (CTI PDFs); ca-certificates -> judge HTTPS.
# tmux + asciinema -> baked so the terminus recording harness finds them already present and
# SKIPS its in-container `apt-get install` at agent setup. That install hits the network every
# run (apt lists are purged above); when it is slow it trips harbor's 120s exec ceiling, which
# surfaces as a RuntimeError past terminus's best-effort guard and fails the whole trial.

# Read-only forensic image at /disk (extracted INTO /disk, not /), security-product feed at /sas.
COPY disk.tar.gz /tmp/
COPY disk.tar.gz.sha256 /tmp/
RUN cd /tmp && sha256sum -c disk.tar.gz.sha256 \\
 && mkdir -p /disk && tar -xzf disk.tar.gz -C /disk \\
 && chmod -R a-w /disk && rm /tmp/disk.tar.gz*

COPY sas-mock /sas
RUN chmod -R a-w /sas
WORKDIR /app
'''
    write_text(out / "environment" / "Dockerfile", text)


def emit_solution(bp: dict, out: Path) -> None:
    """solution/solve.sh — the Oracle solver Harbor's `oracle` agent runs. It writes the
    manifest-derived oracle reports into the workspace, so `harbor run -a oracle` yields
    reward 1 (the task is solvable). Self-contained (heredocs) — the solution is never baked
    into the agent's environment, so the model can't read it."""
    reports = _oracle_reports(bp)
    delim = "RK_ORACLE_EOF"
    lines = [
        "#!/usr/bin/env bash",
        "# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.",
        "set -euo pipefail",
        'OUT="${OUTPUT_PATH:-/app}"',
        'mkdir -p "$OUT"',
    ]
    for name, content in reports.items():
        lines.append(f'cat > "$OUT/{name}" <<\'{delim}\'')
        lines.append(content.rstrip("\n"))
        lines.append(delim)
    write_text(out / "solution" / "solve.sh", "\n".join(lines) + "\n")
    (out / "solution" / "solve.sh").chmod(0o755)


def emit_instruction(bp: dict, out: Path) -> None:
    tmpl = (TEMPLATES / "instruction.md.tmpl").read_text()
    text = (tmpl
            .replace("{{DISK_PATH}}", "/disk")
            .replace("{{SAS_PATH}}", "/sas")
            .replace("{{OUTPUT_PATH}}", "/app")
            .replace("{{SCENARIO}}", bp["scenario"].strip())
            .replace("{{RANGE_ID}}", bp["range_id"]))
    write_text(out / "instruction.md", text)


def emit_sas(bp: dict, out: Path) -> None:
    """The security-product feed: alerts cover only the alerted artifacts, so alert_coverage
    is a property of this feed, not of the disk (doc 03 §6). Lives under environment/ so it is
    inside the Docker build context (COPY sas-mock /sas)."""
    sas = out / "environment" / "sas-mock"
    alerts = [
        {"id": f"ALERT-{i+1:02d}", "chk": a["chk"], "kind": a["kind"],
         "path": a["path"], "capability": a["capability"],
         "summary": f"{a['kind']} observed at {a['path']}"}
        for i, a in enumerate(a for a in bp["artifacts"] if a.get("alerted"))
    ]
    vulns = [] if bp["no_cve_entry"] else [
        {"chk": a["chk"], "cve": a.get("cve", "CVE-UNKNOWN"), "path": a["path"]}
        for a in _by_cap(bp["artifacts"], "VUL")
    ]
    baseline = [
        {"chk": a["chk"], "path": a["path"], "check": a["kind"], "capability": a["capability"]}
        for a in _by_cap(bp["artifacts"], "BAS")
    ]
    write_json(sas / "alerts.json", alerts)
    write_json(sas / "vulns.json", vulns)
    write_json(sas / "baseline.json", baseline)


def emit_assets_disk(bp: dict, out: Path, disk: Path | None) -> None:
    """The forensic image and SAS feed live under environment/ (the Docker build context).
    disk.tar.gz (+ sha256) is produced by build_disk.py after generation; if a prebuilt tar is
    supplied via --disk, place it there directly."""
    env = out / "environment"
    env.mkdir(parents=True, exist_ok=True)
    if disk and disk.exists():
        shutil.copy2(disk, env / "disk.tar.gz")
        digest = hashlib.sha256((env / "disk.tar.gz").read_bytes()).hexdigest()
        write_text(env / "disk.tar.gz.sha256", f"{digest}  disk.tar.gz")
    else:
        write_text(env / "README.md", (
            "# environment/disk.tar.gz is produced by build_disk.py\n\n"
            "Run `python3 build_disk.py tasks/<range>` after generation to synthesise the "
            "forensic image here (+ sha256) and augment `sas-mock/` with the CTI/handoff "
            "materials. The Docker build (context = this directory) bakes it read-only at "
            "`/disk`; `sas-mock/` is baked at `/sas`.\n\n"
            "Every path cited in `tests/manifest.json` must exist inside the image "
            "(QA gate: manifest ↔ disk 100%).\n"
        ))


# ----------------------------------------------------------------------------- verifier

def emit_verifier(bp: dict, out: Path) -> None:
    tests_out = out / "tests"
    if tests_out.exists():
        shutil.rmtree(tests_out)
    shutil.copytree(TEMPLATES / "tests", tests_out)

    # 1. manifest.json — the only per-range input the fixed criteria read.
    write_json(tests_out / "manifest.json", manifest_dict(bp))

    # 2. detection/attribution.toml — render {{CHAIN}} from the manifest, drop the template.
    tmpl_path = tests_out / "detection" / "attribution.toml.tmpl"
    tmpl = tmpl_path.read_text()
    tmpl_path.unlink()
    if bp["judge"].get("attribution", True):
        write_text(tests_out / "detection" / "attribution.toml",
                   tmpl.replace("{{CHAIN}}", _chain_arrow(bp["chain"])))
    if not bp["judge"].get("quality", True):
        (tests_out / "quality" / "q_items.toml").unlink(missing_ok=True)

    # 3. discovery.py — one rk.discovered() per manifest artifact (doc 02 §3.3, "generated").
    write_text(tests_out / "detection" / "discovery.py", _discovery_py(bp))

    # 4. verification.py — one rk.step_verified() per remediation entry.
    write_text(tests_out / "planning" / "verification.py", _verification_py(bp))

    # 5. vendor the rewardkit runtime so the task is self-contained (test.sh runs it).
    shutil.copytree(REWARDKIT, tests_out / "rewardkit",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    # 6. executable bit on test.sh
    (tests_out / "test.sh").chmod(0o755)


def _discovery_py(bp: dict) -> str:
    head = '''# tests/detection/discovery.py  (GENERATED by the task generator from manifest.json)
# One discovery criterion per artifact; evidence/grounding is scored separately by the
# grounding gate (doc 02 §2.3), so this returns a pure 0/1 discovery sub-score.
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion

from criteria import _haystack


@criterion(description="CHK {chk}: artifact {artifact} discovered")
def discovered(workspace: Path, chk: str, artifact: str, match=None) -> float:
    # Path-required: a genuine detection cites the artifact's path (Δ3). `match` needles
    # discriminate checkpoints that share a path (e.g. miner process vs. binary).
    match = list(match or [])
    for f in rk.shared._findings(workspace):
        hay = _haystack(f)
        if artifact in hay and (not match or any(m in hay for m in match)):
            return 1.0
    return 0.0


# --- registrations (silent artifacts upweighted; weights are the manifest's) ---
'''
    lines = [head]
    for a in bp["artifacts"]:
        match = a.get("match")
        match_kw = f", match={match!r}" if match else ""
        weight = a.get("weight", 1.0)
        tag = "  # SILENT" if not a.get("alerted") else ""
        lines.append(
            f'rk.discovered("{a["chk"]}", "{a["path"]}"{match_kw}, weight={weight}){tag}'
        )
    lines.append('rk.silent_artifact_recall(weight=0.0)   # reported, not scored — headline diagnostic')
    if bp.get("no_cve_entry"):
        # Negative-deliverable check is scored only on no-CVE ranges; CVE ranges score the
        # entry via the VUL artifact's discovery instead (so no free 1.0 in detection).
        lines.append('rk.no_false_cve("neg-deliverable", weight=1.5)   # no-CVE ranges only')
    return "\n".join(lines) + "\n"


def _verification_py(bp: dict) -> str:
    head = '''# tests/planning/verification.py  (GENERATED by the task generator from manifest.json)
# One criterion per remediation entry: does the plan block for this finding contain a
# verification action? (doc 02 §3.3)
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion

from criteria import VERIFY_TOKENS, _step_block_for


@criterion(description="remediation step for {chk} includes a verification action")
def step_verified(workspace: Path, chk: str) -> bool:
    m = rk.shared._manifest(workspace)
    rem = next((r for r in m["remediation"] if r["chk"] == chk), None)
    art = next((a for a in m["artifacts"] if a["chk"] == chk), None)
    plan = (workspace / "remediation-plan.md").read_text(errors="replace")
    # Locate the plan block: by artifact if this CHK is an artifact, else by action text.
    key = art if art else {"path": (rem or {}).get("action", chk), "match": [chk]}
    block = _step_block_for(plan, key)
    return bool(block) and any(v in block.lower() for v in VERIFY_TOKENS)


# --- registrations (one per remediation entry) ---
'''
    lines = [head]
    for r in bp.get("remediation", []):
        lines.append(f'rk.step_verified("{r["chk"]}", weight=1.0)')
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------- baselines

def emit_baselines(bp: dict, out: Path) -> None:
    base = out / "baselines"
    _write_reports(base / "oracle", _oracle_reports(bp))
    _write_reports(base / "noop", _noop_reports(bp))
    _write_reports(base / "alert-transcriber", _transcriber_reports(bp))


def _write_reports(dest: Path, reports: dict) -> None:
    for name, text in reports.items():
        write_text(dest / name, text)


def _label(a: dict) -> str:
    """Human label for an artifact that also surfaces its match discriminators, so the oracle
    (the rubric ceiling) names the salient detail a real strong report would — and thereby
    satisfies the path+match discovery rule (doc 02 §3.3)."""
    match = a.get("match") or []
    return f"{a['kind']} ({', '.join(match)})" if match else a["kind"]


def _entities_table(arts: list) -> str:
    rows = ["| Entity | Evidence | ATT&CK |", "|---|---|---|"]
    for a in arts:
        rows.append(f"| {_label(a)} | {_cite(a)} | {a.get('attck', '—')} |")
    return "\n".join(rows)


def _persistence_table(arts: list) -> str:
    rows = ["| Mechanism | Evidence | ATT&CK | Alerted |", "|---|---|---|---|"]
    for a in arts:
        rows.append(f"| {_label(a)} | {_cite(a)} | {a.get('attck', '—')} | "
                    f"{'yes' if a.get('alerted') else '**no**'} |")
    return "\n".join(rows)


def _baseline_table(arts: list) -> str:
    rows = ["| Weakness | Evidence | Capability |", "|---|---|---|"]
    for a in arts:
        rows.append(f"| {_label(a)} | {_cite(a)} | {a['capability']} |")
    return "\n".join(rows)


def _intrusion_report(bp: dict, arts: list) -> str:
    ent, per = _by_cap(arts, "ENT"), _by_cap(arts, "PER")
    entry_steps = sorted(bp["chain"], key=lambda c: c["step"])[:3]
    entry = "; ".join(f"{c['desc']} ({c['attck']})" for c in entry_steps)
    return f'''# Intrusion Report

## Entry Point
{entry}. Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
{_entities_table(ent) if ent else "_None identified._"}

## Persistence Mechanisms
{_persistence_table(per) if per else "_None identified._"}

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
{_chain_arrow(bp["chain"])}

{_chain_edges_md(bp["chain"])}
'''


def _vuln_report(bp: dict, arts: list) -> str:
    if bp["no_cve_entry"]:
        ev = _by_cap(arts, "BAS")
        cites = ", ".join(_cite(a) for a in ev[:3]) or "the baseline checks"
        return f'''# Vulnerability Report

No CVE-driven entry vector was identified. The vulnerability scan returned an empty finding
set (`/sas/vulns.json`), and disk evidence attributes initial access to weak-credential and
configuration weaknesses rather than exploitation of a software vulnerability.

Confidence: high. Evidence: {cites}, empty `/sas/vulns.json`.
'''
    vul = _by_cap(arts, "VUL")
    rows = "\n".join(f"- {a.get('cve','CVE-UNKNOWN')} — {_cite(a)} ({_label(a)})" for a in vul)
    return f'''# Vulnerability Report

A CVE-driven entry vector was identified:

{rows}

Confidence: high. Evidence cited inline.
'''


def _baseline_report(bp: dict, arts: list) -> str:
    bas = _by_cap(arts, "BAS")
    return f'''# Baseline Report

Configuration and baseline weaknesses observed on the host:

{_baseline_table(bas) if bas else "_None identified._"}
'''


def _remediation_plan(bp: dict) -> str:
    precedence = bp["precedence"]
    rem = bp.get("remediation", [])
    by_chk = {a["chk"]: a for a in bp["artifacts"]}
    out = ["# Remediation Plan", ""]
    n = 0
    for pnum, phase in enumerate(precedence):
        entries = [r for r in rem if r.get("phase") == phase]
        if not entries:
            continue
        out.append(f"## P{pnum} — {phase.title()}")
        for r in entries:
            n += 1
            # Name the artifact the step remediates (its cited path), so plan-coverage and
            # step-verification can link the step to its finding — a good plan names the
            # file it is acting on, and the oracle must model that.
            art = by_chk.get(r["chk"])
            target = f" — target: {_cite(art)}" if art else ""
            out.append(f"{n}. {r['action']}{target}.")
            if r.get("verify"):
                out.append(f"   - Verify: `{r['verify']}`")
            if r.get("risk_class"):
                out.append(f"   - Risk: {r['risk_class']}")
        out.append("")
    if n == 0:
        out.append("_No remediation steps defined in the manifest._")
    return "\n".join(out)


def _progress(bp: dict) -> str:
    return f'''# Progress

Investigation timeline for `{bp['range_id']}`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: {_chain_prose(bp["chain"])}.
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
'''


def _oracle_reports(bp: dict) -> dict:
    arts = bp["artifacts"]
    return {
        "progress.md": _progress(bp),
        "intrusion-report.md": _intrusion_report(bp, arts),
        "vuln-report.md": _vuln_report(bp, arts),
        "baseline-report.md": _baseline_report(bp, arts),
        "remediation-plan.md": _remediation_plan(bp),
    }


def _transcriber_reports(bp: dict) -> dict:
    """Reports built from the alerts only — correct and well-cited, but zero silent artifacts.
    Isolates P1: a model near this baseline (not the oracle) is exhibiting reactive tunnel
    vision (doc 04 §7.3)."""
    alerted = [a for a in bp["artifacts"] if a.get("alerted")]
    bp_alerted = dict(bp, artifacts=alerted)
    reports = {
        "progress.md": "# Progress\n\nReported every alert in `/sas`. Did not investigate "
                       "beyond the alerts.\n",
        "intrusion-report.md": _intrusion_report(bp_alerted, alerted),
        "vuln-report.md": _vuln_report(bp, alerted),
        "baseline-report.md": _baseline_report(bp, alerted),
        "remediation-plan.md": _remediation_plan(
            dict(bp, remediation=[r for r in bp.get("remediation", [])
                                  if any(a["chk"] == r["chk"] for a in alerted)])
        ),
    }
    return reports


NOOP_REPORTS = {
    "progress.md": "# Progress\n\nInvestigated the host and reviewed the available evidence.\n",
    "intrusion-report.md": '''# Intrusion Report

## Executive Summary
The host shows indicators consistent with a compromise involving unauthorized access and
subsequent malicious activity. The attacker appears to have gained entry, established
persistence, and deployed a payload.

## Attack Chain
1. Initial access via an exposed remote-access service.
2. Privilege escalation to administrative context.
3. Deployment of a malicious payload.
4. Installation of persistence mechanisms.
5. Anti-forensic activity to hinder investigation.

## Entities
Several suspicious files, processes, and network endpoints were identified during the
investigation.

## Impact
Confidentiality, integrity, and availability of the host should be considered compromised.
A full rebuild is recommended.
''',
    "vuln-report.md": "# Vulnerability Report\n\nThe host likely contains exploitable "
                      "weaknesses. A full vulnerability assessment is recommended.\n",
    "baseline-report.md": "# Baseline Report\n\nThe host's configuration deviates from "
                          "hardening baselines in several respects.\n",
    "remediation-plan.md": '''# Remediation Plan

## P0 — Immediate
- Isolate the host from the network.
- Terminate malicious processes.
- Remove malicious files.

## P1 — Short term
- Rotate all credentials.
- Harden remote-access configuration.
- Apply outstanding patches.

## P2 — Follow up
- Review logs for lateral movement.
- Rebuild the host from a known-good image.
''',
}


def _noop_reports(bp: dict) -> dict:
    return dict(NOOP_REPORTS)
