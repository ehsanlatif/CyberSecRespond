#!/usr/bin/env python3
"""One-time authoring helper: distil the raw NVD + MITRE ATT&CK downloads into the small,
license-clean reference cache build_disk.py reads. Re-run only when refreshing sources.

  NVD data is US-government work (public domain).
  MITRE ATT&CK is (c) The MITRE Corporation, licensed CC BY 4.0 — attribution baked into
  every generated artifact that uses a technique name.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRATCH = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE

# ---- ATT&CK: external_id -> {name, tactic} for every technique id we use -----------------
NEEDED = ("T1003.001 T1021.001 T1021.004 T1037.004 T1048 T1048.003 T1053.003 T1053.005 "
          "T1059.001 T1059.004 T1070.001 T1070.002 T1070.006 T1078 T1098.004 T1110 T1133 "
          "T1190 T1210 T1486 T1491.001 T1496 T1505.003 T1543.002 T1543.003 T1546.003 "
          "T1546.004 T1547.001 T1548.003 T1560.001 T1574.001 T1574.006 T1610 T1611").split()

bundle = json.loads((SCRATCH / "enterprise-attack.json").read_text())
names = {}
for obj in bundle["objects"]:
    if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
        continue
    ext = next((r for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack" and r.get("external_id", "").startswith("T")), None)
    if not ext:
        continue
    tid = ext["external_id"]
    tactic = (obj.get("kill_chain_phases") or [{}])[0].get("phase_name", "")
    names[tid] = {"name": obj.get("name", ""), "tactic": tactic}

# Authoritative fallback for ids the bundle snapshot only carries as revoked duplicates
# (this master snapshot has stale 'stealth'-tactic copies of the T1070 log-clearing subs).
FALLBACK = {
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "defense-evasion"},
    "T1070.002": {"name": "Clear Linux or Mac System Logs", "tactic": "defense-evasion"},
}
out = {t: names.get(t) or FALLBACK.get(t, {"name": "Unknown Technique", "tactic": ""})
       for t in NEEDED}
missing = [t for t in NEEDED if t not in names and t not in FALLBACK]
(HERE / "attack_names.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
print("attack_names.json: %d ids (%d missing: %s)" % (len(out), len(missing), missing))

# ---- NVD: trim each CVE to the fields a vuln analyst actually cites -----------------------
cvedir = HERE / "cve"
cvedir.mkdir(exist_ok=True)
for raw in sorted(SCRATCH.glob("CVE-*.raw.json")):
    d = json.loads(raw.read_text())
    v = d["vulnerabilities"][0]["cve"]
    desc = next((x["value"] for x in v["descriptions"] if x["lang"] == "en"), "")
    metrics = v.get("metrics", {})
    m31 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
    cdata = m31.get("cvssData", {})
    cwes = sorted({desc2["value"] for w in v.get("weaknesses", [])
                   for desc2 in w.get("description", []) if desc2["value"].startswith("CWE")})
    refs = [r["url"] for r in v.get("references", [])][:6]
    trimmed = {
        "id": v["id"],
        "published": v.get("published", "")[:10],
        "lastModified": v.get("lastModified", "")[:10],
        "cvss_version": cdata.get("version", ""),
        "cvss_base_score": cdata.get("baseScore"),
        "cvss_severity": m31.get("baseSeverity", cdata.get("baseSeverity", "")),
        "cvss_vector": cdata.get("vectorString", ""),
        "cwe": cwes,
        "description": desc,
        "references": refs,
        "source": "NVD (nvd.nist.gov), US Government public-domain data",
    }
    (cvedir / (v["id"] + ".json")).write_text(json.dumps(trimmed, indent=2) + "\n")
    print("  %s  CVSS %s %s  %s" % (v["id"], trimmed["cvss_base_score"],
                                    trimmed["cvss_severity"], ",".join(cwes) or "-"))
