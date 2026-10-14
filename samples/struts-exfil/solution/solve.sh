#!/usr/bin/env bash
# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.
set -euo pipefail
OUT="${OUTPUT_PATH:-/app}"
mkdir -p "$OUT"
cat > "$OUT/progress.md" <<'RK_ORACLE_EOF'
# Progress

Investigation timeline for `struts-exfil`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1190 — Struts2 OGNL RCE (CVE-2023-50164); step 2 T1505.003 — JSP webshell planted (after step 1); step 3 T1059.004 — shell execution (after step 2); step 4 T1560.001 — stage archive for exfil (after step 3); step 5 T1048 — exfiltrate over HTTPS (after step 4); step 6 T1098.004 — authorized_keys backdoor (after step 3); step 7 T1053.003 — cron persistence (after step 3); step 8 T1070.002 — selective auth-log wipe (after step 3).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
RK_ORACLE_EOF
cat > "$OUT/intrusion-report.md" <<'RK_ORACLE_EOF'
# Intrusion Report

## Entry Point
Struts2 OGNL RCE (CVE-2023-50164) (T1190); JSP webshell planted (T1505.003); shell execution (T1059.004). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| exfil-archive (tar, dump) | `/tmp/.cache/dump.tar.gz` | T1560.001 |
| exfil-endpoint (POST, exfil) | `/var/log/tomcat/access-exfil.log` | T1048 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| ssh-key-backdoor (ssh-ed25519, attacker) | `/root/.ssh/authorized_keys` | T1098.004 | **no** |
| cron (curl, beacon) | `/var/spool/cron/tomcat` | T1053.003 | yes |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1190 → T1505.003 → T1059.004 → {T1560.001, T1098.004, T1053.003, T1070.002}

- T1190 → T1505.003
- T1505.003 → T1059.004
- T1059.004 → T1560.001
- T1560.001 → T1048
- T1059.004 → T1098.004
- T1059.004 → T1053.003
- T1059.004 → T1070.002
RK_ORACLE_EOF
cat > "$OUT/vuln-report.md" <<'RK_ORACLE_EOF'
# Vulnerability Report

A CVE-driven entry vector was identified:

- CVE-2023-50164 — `/opt/tomcat/webapps/ROOT/static/upload.jsp` (webshell (jsp, ognl))

Confidence: high. Evidence cited inline.
RK_ORACLE_EOF
cat > "$OUT/baseline-report.md" <<'RK_ORACLE_EOF'
# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| vulnerable-lib (struts2, 2.5) | `/opt/tomcat/lib/struts2-core.jar` | BAS-01 |
RK_ORACLE_EOF
cat > "$OUT/remediation-plan.md" <<'RK_ORACLE_EOF'
# Remediation Plan

## P0 — Contain
1. block the exfil destination and attacker IP at the egress firewall.
   - Verify: `iptables -L OUTPUT -n | grep <ip>`
   - Risk: network

## P1 — Eradicate
2. quarantine upload.jsp and its drop directory — target: `/opt/tomcat/webapps/ROOT/static/upload.jsp`.
   - Verify: `! test -f /opt/tomcat/webapps/ROOT/static/upload.jsp`
   - Risk: service
3. remove the staged exfil archive — target: `/tmp/.cache/dump.tar.gz`.
   - Verify: `! test -f /tmp/.cache/dump.tar.gz`
   - Risk: runtime
4. remove the attacker key from /root/.ssh/authorized_keys — target: `/root/.ssh/authorized_keys`.
   - Verify: `! grep -q attacker /root/.ssh/authorized_keys`
   - Risk: auth
5. remove the tomcat cron entry — target: `/var/spool/cron/tomcat`.
   - Verify: `! test -f /var/spool/cron/tomcat`
   - Risk: runtime

## P2 — Harden
6. upgrade struts2 past the fixed release — target: `/opt/tomcat/lib/struts2-core.jar`.
   - Verify: `rpm -q struts2 shows a patched version`
   - Risk: service

## P3 — Rotate
7. rotate application, root, and any exfiltrated credentials.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. confirm the OGNL exploit path no longer executes.
   - Verify: `replay a benign probe and confirm it is rejected`
   - Risk: service
9. restart tomcat and confirm service health.
   - Verify: `systemctl is-active tomcat and HTTP 200 on /`
   - Risk: service
RK_ORACLE_EOF
