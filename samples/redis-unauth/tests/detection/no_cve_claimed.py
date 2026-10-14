# tests/detection/no_cve_claimed.py  (FIXED — Tier 1, the negative deliverable)
import re
from pathlib import Path

import rewardkit as rk
from rewardkit import criterion

CVE = re.compile(r"cve-\d{4}-\d{4,7}")
NEGATED = ("no cve", "not cve", "no known cve", "ruled out", "rather than",
           "not driven by", "no vulnerability-driven", "not vulnerability-driven",
           "no software vulnerability", "excluded", "is not", "no exploited",
           # an analyst rejects a planted / false CVE (Delta-2 reconciliation) with these too
           "false", "incorrect", "whereas", "not applicable", "n/a", "does not apply",
           "rejected", "reject", "not exploited", "unrelated", "does not", "no rdp",
           "not the entry", "not relevant", "cannot apply", "disproven", "invalid", "refuted")
CONCLUDES_NONE = ("no cve", "not cve-driven", "no vulnerability-driven entry",
                  "misconfiguration rather than", "no known cve", "no software vulnerability",
                  "0 cves", "no cves", "none (0", "0 cve", "cve: none",
                  "exploited: none", "exploited for entry: none")


@criterion(description="vuln-report correctly concludes no CVE-driven entry")
def no_false_cve(workspace: Path, tag) -> float:
    """The negative-deliverable check. `tag` is a required scheduling marker: it forces this
    criterion to be registered EXPLICITLY (build.py emits `rk.no_false_cve(...)` only for
    no-CVE ranges) rather than auto-scheduled, so a CVE range never contributes a free 1.0 to
    the detection axis. A CVE id is a false attribution only when asserted affirmatively —
    naming a CVE to rule it out ("entry was weak creds, not CVE-2021-44228") is correct, not
    fabrication (doc 04 §6)."""
    m = rk.shared._manifest(workspace)
    if not m.get("no_cve_entry"):
        return 1.0  # CVE-entry ranges are scored by their own discovery criteria
    p = workspace / "vuln-report.md"
    if not p.exists():
        return 0.0
    text = p.read_text(errors="replace").lower()
    lines = text.splitlines()
    win = 3  # a CVE named to be rejected often carries the rejection on a NEARBY line, not the same one
    for i, line in enumerate(lines):
        if CVE.search(line):
            ctx = " ".join(lines[max(0, i - win): i + win + 1])
            if not any(n in ctx for n in NEGATED):
                return 0.0  # affirmatively attributes entry to a CVE that does not exist
    asserts_none = any(phrase in text for phrase in CONCLUDES_NONE)
    return 1.0 if asserts_none else 0.3  # silence != correct conclusion
