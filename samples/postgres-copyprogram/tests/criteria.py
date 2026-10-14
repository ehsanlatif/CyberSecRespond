# tests/criteria.py
from __future__ import annotations
#
# Shared library for the post-compromise DFIR verifier. This file is FIXED — it is identical
# for every range in the subdomain. Nothing here is range-specific; the only per-range input
# is manifest.json (doc 02 §3.0). The @criterion(shared=True) loaders are exposed to the
# tier files as rk.shared.<name>; the plain functions below them are framework-agnostic
# helpers imported directly (`from criteria import _dag, ...`).
import json
import os
import re
from pathlib import Path

from rewardkit import criterion

# Mount locations default to the container paths but are overridable via env, so the runner
# (and selftest) can point them at real or synthesised directories without editing this file.
TESTS_DIR = Path(os.environ.get("RK_TESTS", "/tests"))

# Citations MUST be backtick-delimited: `/abs/path` or `/abs/path:line`. Requiring the
# backticks stops bare slashes in prose ("and/or", "TCP/IP", "24/7") from being parsed as
# paths and then flagged as fabrication. The path class excludes ':' so the optional
# ':line' suffix splits unambiguously (doc 02 §3.3).
CITE = re.compile(r"`(/[^`\s:]+)(?::(\d+))?`")

# Read-only evidence mounts the agent is given (doc 02 §2.3). Citations are resolved by
# mount prefix, NOT by blindly stripping the leading '/':
#   - a citation beginning with a mount prefix ("/sas/alerts.json") resolves literally under
#     that mount;
#   - any other host-absolute citation ("/etc/ssh/sshd_config") is a path *inside the
#     forensic image* and resolves under the primary host root (/disk) — never against the
#     analysis machine's own filesystem.
EVIDENCE_MOUNTS = {"/sas": Path(os.environ.get("RK_SAS", "/sas")),
                   "/disk": Path(os.environ.get("RK_DISK", "/disk"))}
HOST_ROOT = "/disk"

# The three report files findings are parsed from. progress.md and remediation-plan.md are
# handled by their own criteria and are not scanned for detection findings.
REPORT_FILES = ("intrusion-report.md", "vuln-report.md", "baseline-report.md")

# ATT&CK technique id, e.g. T1110 or T1546.004.
ATTCK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@criterion(shared=True)
def _manifest(workspace: Path) -> dict:
    """Ground truth for this range (generated corpus) or hand-extracted (SecRespond)."""
    return json.loads((TESTS_DIR / "manifest.json").read_text())


@criterion(shared=True)
def _findings(workspace: Path) -> list:
    """Parse (claim, citations) pairs out of the agent's markdown reports."""
    out = []
    for name in REPORT_FILES:
        p = workspace / name
        if not p.exists():
            continue
        for line in p.read_text(errors="replace").splitlines():
            cites = CITE.findall(line)
            if cites:
                out.append({"claim": line.strip(), "citations": cites, "source": name})
    return out


def _candidates(path: str) -> list:
    """Real filesystem candidate(s) a citation could resolve to, by mount prefix."""
    p = "/" + path.lstrip("/")
    for prefix, root in EVIDENCE_MOUNTS.items():
        if p == prefix or p.startswith(prefix + "/"):
            return [root / p[len(prefix):].lstrip("/")]
    # No mount prefix -> a host path inside the forensic image.
    return [EVIDENCE_MOUNTS[HOST_ROOT] / p.lstrip("/")]


# Ubiquitous baseline files present on essentially every real Linux host. A generated range's
# disk image is deliberately sparse (only scenario-relevant files), so an agent that cites one
# of these for a baseline finding is not fabricating — the file would exist on the real host.
# Kept as an explicit exact-path allowlist (NOT a directory prefix) so genuinely invented paths
# such as /uploads/shell.php or /lib/.hide.so are still classified as fabrication.
UBIQUITOUS_PATHS = frozenset({
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
    "/etc/hosts", "/etc/fstab", "/etc/crontab", "/etc/os-release", "/etc/resolv.conf",
    "/etc/login.defs", "/etc/nsswitch.conf", "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
    "/etc/pam.d/sshd", "/etc/pam.d/common-auth", "/usr/sbin/nologin", "/sbin/nologin",
    "/bin/ls", "/bin/bash", "/bin/sh", "/bin/false", "/var/run/docker.sock",
})


@criterion(shared=True)
def _grounding(workspace: Path):
    """Return a classifier path -> {'resolved','plausible','fabricated'} so every criterion
    shares one filesystem view of the evidence mounts (doc 02 §2.3)."""

    def classify(path: str) -> str:
        cands = _candidates(path)
        if any(c.exists() for c in cands):
            return "resolved"
        if any(c.parent.exists() for c in cands):
            return "plausible"          # wrong file/line inside a real directory
        # A sparse synthetic image can omit standard baseline files that exist on every real
        # host of this OS; citing one is a benign baseline reference, not fabrication.
        if "/" + path.lstrip("/") in UBIQUITOUS_PATHS:
            return "plausible"
        return "fabricated"             # parent directory absent under every mount

    return classify


# --------------------------------------------------------------------------------------
# Framework-agnostic helpers (pure Python; no rewardkit dependency). Imported by the tier
# files. The docs (doc 02/04) leave these as `_helpers`; here they are implemented in full.
# --------------------------------------------------------------------------------------

def _haystack(finding: dict) -> str:
    """All searchable text of a finding: its claim plus its cited path strings."""
    return finding["claim"] + " " + " ".join(c[0] for c in finding["citations"])


# Function words dropped when a remediation ACTION phrase is turned into locator needles, so a
# common connective can't mislocate a step. Salient verbs/nouns (block, rotate, firewall, …) stay.
_STOP = {"the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "is", "are", "be", "that",
         "this", "with", "from", "its", "it", "took", "effect", "affected", "off", "host", "then",
         "all", "any", "not", "no", "only", "via", "per", "each", "reachable"}


def _needles(artifact: dict) -> list:
    """Locator needles for finding an artifact's plan block. For an artifact (a real /path): the
    path, its basename, and any `match` terms. For a remediation-only CHK — whose "path" is the
    manifest ACTION phrase, not a filesystem path — the salient content words of that phrase, so
    an agent's differently-worded step ("Network Containment (Block Attacker IP)") still matches
    the manifest action ("block attacker source IP inbound") that no agent reproduces verbatim."""
    path = artifact.get("path", "")
    match = list(artifact.get("match") or [])
    if path.startswith("/"):
        base = path.rstrip("/").split("/")[-1]
        return [n for n in ([path, base] + match) if n]
    words = [w for w in re.findall(r"[a-z0-9][a-z0-9-]{2,}", path.lower()) if w not in _STOP]
    return [n for n in (words + match) if n]


def _artifact_mentioned(findings: list, artifact: dict) -> bool:
    """An artifact counts as discovered only if a finding cites its full PATH (Δ3 requires
    citations, so a genuine detection names the path) AND — when the artifact has `match`
    discriminators — at least one of them co-occurs. Requiring the path avoids the substring
    collisions that would otherwise inflate silent-recall (e.g. two artifacts sharing a name
    fragment, or two checkpoints sharing one path distinguished only by `match`)."""
    path = artifact.get("path", "")
    match = [m.lower() for m in (artifact.get("match") or [])]
    if not path:
        return False
    pl = path.lower()
    for f in findings:
        hay = _haystack(f).lower()
        if pl in hay and (not match or any(m in hay for m in match)):
            return True
    return False


def _detected_chks(findings: list, manifest: dict) -> list:
    """CHK ids of manifest artifacts the agent actually named in a report."""
    return [a["chk"] for a in manifest["artifacts"] if _artifact_mentioned(findings, a)]


# ---- attack-chain DAG (doc 02 §3.4) ----

def _dag(chain: list) -> dict:
    """Build a DAG from manifest['chain']. Nodes = ATT&CK ids; edges = (upstream, node)
    pairs derived from `depends_on` (defaulting to the previous step when absent)."""
    by_step = {c["step"]: c for c in chain}
    nodes = {c["attck"] for c in chain}
    edges = set()
    for c in chain:
        deps = c.get("depends_on")
        if deps is None and c["step"] > 1 and (c["step"] - 1) in by_step:
            deps = [c["step"] - 1]
        for d in deps or []:
            if d in by_step:
                edges.add((by_step[d]["attck"], c["attck"]))
    return {"nodes": nodes, "edges": edges}


_CHAIN_HEADING = re.compile(r"chain|att&ck|mitre|technique", re.I)


def _heading_level(line: str):
    """Markdown heading level (count of leading '#'), or None if the line is not a heading."""
    s = line.lstrip()
    if not s.startswith("#"):
        return None
    return len(s) - len(s.lstrip("#"))


def _chain_section(text: str) -> str:
    """Concatenate every section whose heading names the attack chain OR the ATT&CK / technique
    mapping, each sliced until the next heading of the same-or-higher level so its sub-sections
    stay attached. This credits ATT&CK ids an analyst records in a 'MITRE ATT&CK Technique
    Mapping' table as well as those under an 'Attack Chain' heading, while still excluding
    incidental ids in an entities table (whose heading matches none of the cues). Falls back to
    the whole report when no such heading exists."""
    lines = text.splitlines()
    n = len(lines)
    regions = []
    for i, l in enumerate(lines):
        lvl = _heading_level(l)
        if lvl is not None and _CHAIN_HEADING.search(l):
            end = n
            for j in range(i + 1, n):
                lj = _heading_level(lines[j])
                if lj is not None and lj <= lvl:
                    end = j
                    break
            regions.append("\n".join(lines[i + 1:end]))
    if not regions:
        return text
    return "\n".join(regions)


def _parse_chain(report_path: Path) -> dict:
    """Parse the agent's reconstructed chain from intrusion-report.md.

    Nodes = ATT&CK ids mentioned. Edges are read from arrow notation on a line, tolerant of
    both linear (`A -> B -> C`) and branching/brace (`A -> {B, C, D}`) forms:
      - a non-brace segment with several ids chains them (a -> b -> c) and connects to
        neighbours via its first/last id;
      - a brace segment `{B, C, D}` treats its ids as siblings — each receives from the
        previous tail and sends to the next head.
    """
    nodes, edges = set(), set()
    if not report_path.exists():
        return {"nodes": nodes, "edges": edges}
    for raw in _chain_section(report_path.read_text(errors="replace")).splitlines():
        line = raw.replace("→", "->")
        ids_all = ATTCK.findall(line)
        nodes.update(ids_all)
        if "->" not in line:
            continue
        segs = line.split("->")
        heads, tails = [], []
        for seg in segs:
            ids = ATTCK.findall(seg)
            if not ids:
                heads.append([]); tails.append([]); continue
            if "{" in seg:                       # brace set: siblings
                heads.append(ids); tails.append(ids)
            else:                                 # ordered ids chain within the segment
                for a, b in zip(ids, ids[1:]):
                    edges.add((a, b))
                heads.append(ids[:1]); tails.append(ids[-1:])
        for left, right in zip(range(len(segs)), range(1, len(segs))):
            for a in tails[left]:
                for b in heads[right]:
                    edges.add((a, b))
    return {"nodes": nodes, "edges": edges}


def _ged(pred: dict, gt: dict) -> int:
    """Graph edit distance approximated as the symmetric difference of node sets plus the
    symmetric difference of edge sets (deletions + insertions). Deleting a node also deletes
    its incident edges, so both terms are counted (doc 02 §3.4)."""
    node_diff = len(pred["nodes"] ^ gt["nodes"])
    edge_diff = len(pred["edges"] ^ gt["edges"])
    return node_diff + edge_diff


# ---- remediation plan parsing (doc 02 §3.4, §3.3) ----

VERIFY_TOKENS = ("verif", "confirm", "re-run", "rerun", "recheck", "revalidate", "validate",
                 "validation", "systemctl status", "systemctl is-active", "systemctl is-enabled",
                 "is-active", "is-enabled", "restart", "test", "check that", "check for",
                 "checking", "ensure", "assert", "expect", "returns empty", "returns no",
                 "no longer", "not present", "== 0",
                 # concrete commands an analyst runs to confirm a fix took effect
                 "pgrep", "ps aux", "sshd -t", "netstat", "ss -", "iptables -l", "sudo -l",
                 "docker ps")

PHASE_CUES = {
    "contain":   ("contain", "isolate", "block", "disconnect", "cordon"),
    "eradicate": ("eradicate", "remove", "delete", "kill", "terminate", "disable",
                  "quarantine", "clean", "revoke", "purge"),
    "harden":    ("harden", "permitrootlogin", "passwordauthentication", "maxauthtries",
                  "restrict", "reconfigure", "bind-address", "patch", "lock down"),
    "rotate":    ("rotate", "reset password", "reset credential", "change credential",
                  "new key", "rekey", "re-key", "rotate credentials"),
    "verify":    ("verify", "confirm", "restart", "re-run", "recheck", "validate",
                  "is-active", "health", "status", "http 200"),
}


def _blocks(plan: str) -> list:
    """Split a remediation plan into step blocks. A block starts at a numbered item, a
    bullet, or a header, and runs until the next such marker (sub-bullets included)."""
    lines = plan.splitlines()
    starts = []
    marker = re.compile(r"^\s*(?:#{1,6}\s|\d+[.)]\s|[-*+]\s)")
    for i, line in enumerate(lines):
        if marker.match(line):
            starts.append(i)
    if not starts:
        return [plan] if plan.strip() else []
    starts.append(len(lines))
    return ["\n".join(lines[starts[k]:starts[k + 1]]) for k in range(len(starts) - 1)]


def _coarse_blocks(plan: str) -> list:
    """Split a plan into step blocks at headers and numbered items ONLY — not at bullets — so
    a step keeps its sub-bullets (e.g. a `- Verify: ...` line stays with its step). Used by
    step lookup; `_blocks` (which also splits at bullets) is used by phase ordering."""
    lines = plan.splitlines()
    marker = re.compile(r"^\s*(?:#{1,6}\s|\d+[.)]\s)")
    starts = [i for i, line in enumerate(lines) if marker.match(line)]
    if not starts:
        return [plan] if plan.strip() else []
    starts.append(len(lines))
    return ["\n".join(lines[starts[k]:starts[k + 1]]) for k in range(len(starts) - 1)]


_NONSTEP_HEADING = re.compile(
    r"change[\s_-]*ticket|reconcil|executive summary|\bsummary\b|overview|\bscope\b|"
    r"table of contents|background|introduction|objective|appendix", re.I)


def _block_heading(block: str) -> str:
    """First heading line of a coarse block (falls back to its first line)."""
    for line in block.splitlines():
        if line.lstrip().startswith("#"):
            return line
    lines = block.splitlines()
    return lines[0] if lines else ""


def _step_block_for(plan: str, artifact: dict) -> str:
    """Return the remediation STEP block that references this artifact (by path, basename, or a
    match needle); empty string if none.

    Blocks whose heading marks them as a non-step section — the reconciled change ticket (which
    Delta-2 requires the agent to reproduce, and which legitimately names every artifact path
    near the top of the plan), an executive summary, an overview — are skipped so they cannot
    shadow the real remediation step below them. Among the remaining step blocks, one that
    carries a verification action is preferred (so a plan that verifies fixes in a dedicated
    validation phase is credited), then the most specific by locator-hit count."""
    path = artifact.get("path", "")
    needles = [n.lower() for n in _needles(artifact)]
    if not needles:
        return ""

    def hits(b):
        bl = b.lower()
        return sum(1 for n in needles if n in bl)

    # A path key identifies its step by a single strong locator; a remediation ACTION phrase
    # needs >=2 salient words to co-occur so a lone common word can't mislocate the step.
    min_hits = 2 if (not path.startswith("/") and len(needles) >= 2) else 1
    matches = [b for b in _coarse_blocks(plan) if hits(b) >= min_hits]
    if not matches:
        return ""
    steps = [b for b in matches if not _NONSTEP_HEADING.search(_block_heading(b))]
    pool = steps or matches  # if the ONLY mention is in a non-step section, fall back to it
    # A plan may verify a fix in-step or in a dedicated validation phase; credit either by
    # preferring, among the step blocks, one that carries a verification action, then the
    # most-specific by locator-hit count; ties resolve to document order.
    verified = [b for b in pool if any(v in b.lower() for v in VERIFY_TOKENS)]
    pool = verified or pool
    return max(pool, key=hits)


def _phase_of(text: str) -> str:
    """Best-guess remediation phase for a block of plan text, by keyword cue."""
    low = text.lower()
    # Explicit headers like "P0 — Contain" win.
    for phase, cues in PHASE_CUES.items():
        if re.search(rf"\b{phase}\b", low):
            return phase
    best, best_hits = None, 0
    for phase, cues in PHASE_CUES.items():
        hits = sum(1 for c in cues if c in low)
        if hits > best_hits:
            best, best_hits = phase, hits
    return best or "eradicate"


_HEADER_RE = re.compile(r"^\s*#{1,6}\s")
_STEP_RE = re.compile(r"^\s*\d+[.)]\s")


def _header_phase(text: str) -> str | None:
    low = text.lower()
    for phase in ("contain", "eradicate", "harden", "rotate", "verify"):
        if phase in low:
            return phase
    return None


def _ordered_steps(plan: str) -> list:
    """Phase label per top-level remediation step, in document order (doc 02 §3.4).

    Prefers the phase of the enclosing header ("## P1 — Eradicate"); sub-bullets such as
    "- Verify: ..." are NOT steps and must not be phase-labelled (that spuriously injected a
    'verify' step into every section). Falls back to per-step keyword classification when the
    plan has no phase headers."""
    phases, current = [], None
    for line in plan.splitlines():
        if _HEADER_RE.match(line):
            p = _header_phase(line)
            if p:
                current = p
            continue
        if _STEP_RE.match(line):
            phases.append(current or _phase_of(line))
    if not phases:  # unstructured plan — fall back to block classification
        return [_phase_of(b) for b in _blocks(plan) if b.strip()]
    return phases


def _count_precedence_violations(steps: list, precedence: list) -> int:
    """Count adjacent out-of-order transitions against the precedence order."""
    idx = [precedence.index(p) for p in steps if p in precedence]
    return sum(1 for a, b in zip(idx, idx[1:]) if a > b)
