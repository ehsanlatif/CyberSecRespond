# tests/structure/required_sections.py  (FIXED — structure gate, required_pass)
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion

# Minimal section contract each report must satisfy (case-insensitive substring match).
# Deliberately loose — the gate checks SHAPE, not content quality. In particular it does NOT
# require verification language in the plan (that is a Tier-1 plan score, not a structure
# gate), so a well-formed but evidence-free no-op report still passes structure.
# Each requirement is either a substring that must appear, or a tuple of alternatives of which
# at least one must appear. This is a SHAPE gate only. The intrusion report must contain an
# attack-chain section (the entry point is its first step); it is NOT additionally required to
# contain the literal word "entry" — the instruction asks for "attack chain, evidence, entities,
# persistence, impact", and a report that names the entry via a MITRE technique such as
# "Exploitation of Remote Services (T1210)" or "Initial Access" must not fail a shape check.
# Entry-point QUALITY is scored on the detection axis (chain step 1 / discovery), not here.
REQUIRED_SECTIONS = {
    "intrusion-report.md": ("chain",),                # attack chain (entry point = its step 1)
    "vuln-report.md":      ("vuln",),                 # a vulnerability section
    "baseline-report.md":  ("baseline",),             # baseline weaknesses
    "remediation-plan.md": ("remediat",),             # a remediation plan
}


def _headings(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if l.lstrip().startswith("#")).lower()


@criterion(description="each report contains its required sections", required_pass=True)
def required_sections(workspace: Path) -> bool:
    for name, needles in REQUIRED_SECTIONS.items():
        p = workspace / name
        if not p.exists():
            return False
        blob = p.read_text(errors="replace").lower()
        heads = _headings(blob)
        for n in needles:
            alts = (n,) if isinstance(n, str) else n
            if not any(a in heads or a in blob for a in alts):
                return False
    return True
