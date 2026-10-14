#!/usr/bin/env bash
# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.
set -euo pipefail
OUT="${OUTPUT_PATH:-/app}"
mkdir -p "$OUT"
cat > "$OUT/progress.md" <<'RK_ORACLE_EOF'
# Progress

Investigation timeline for `log4shell-webshell`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1190 — Log4Shell RCE (CVE-2021-44228); step 2 T1505.003 — JSP webshell planted (after step 1); step 3 T1059.004 — reverse shell execution (after step 2); step 4 T1053.003 — cron persistence (after step 3); step 5 T1543.002 — systemd persistence (after step 3); step 6 T1070.006 — timestomp webshell (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
RK_ORACLE_EOF
cat > "$OUT/intrusion-report.md" <<'RK_ORACLE_EOF'
# Intrusion Report

## Entry Point
Log4Shell RCE (CVE-2021-44228) (T1190); JSP webshell planted (T1505.003); reverse shell execution (T1059.004). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| reverse-shell (process, reverse, bash -i) | `/tmp/.sysd` | T1059.004 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| cron | `/etc/cron.d/apache-cache` | T1053.003 | **no** |
| systemd | `/etc/systemd/system/apache-cache.service` | T1543.002 | yes |
| webshell-secondary (jsp, webshell) | `/var/lib/tomcat9/webapps/ROOT/static/.helper.jsp` | T1505.003 | **no** |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1190 → T1505.003 → {T1059.004, T1070.006}

- T1190 → T1505.003
- T1505.003 → T1059.004
- T1059.004 → T1053.003
- T1059.004 → T1543.002
- T1505.003 → T1070.006
RK_ORACLE_EOF
cat > "$OUT/vuln-report.md" <<'RK_ORACLE_EOF'
# Vulnerability Report

A CVE-driven entry vector was identified:

- CVE-2021-44228 — `/var/lib/tomcat9/webapps/ROOT/static/status.jsp` (webshell (jndi, ldap, webshell))

Confidence: high. Evidence cited inline.
RK_ORACLE_EOF
cat > "$OUT/baseline-report.md" <<'RK_ORACLE_EOF'
# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| vulnerable-config (log4j, 2.14) | `/opt/app/log4j2.xml` | BAS-01 |
RK_ORACLE_EOF
cat > "$OUT/remediation-plan.md" <<'RK_ORACLE_EOF'
# Remediation Plan

## P0 — Contain
1. block attacker source IP inbound at the edge.
   - Verify: `iptables -L INPUT -n | grep <ip>`
   - Risk: network

## P1 — Eradicate
2. quarantine the JSP webshell and remove the drop directory — target: `/var/lib/tomcat9/webapps/ROOT/static/status.jsp`.
   - Verify: `! test -f /var/lib/tomcat9/webapps/ROOT/static/status.jsp`
   - Risk: service
3. terminate the reverse-shell process — target: `/tmp/.sysd`.
   - Verify: `pgrep -f .sysd returns empty`
   - Risk: runtime
4. remove /etc/cron.d/apache-cache — target: `/etc/cron.d/apache-cache`.
   - Verify: `! test -f /etc/cron.d/apache-cache`
   - Risk: runtime
5. disable and remove apache-cache.service — target: `/etc/systemd/system/apache-cache.service`.
   - Verify: `systemctl is-enabled apache-cache 2>&1 | grep -qv enabled`
   - Risk: service
6. remove the secondary .helper.jsp webshell — target: `/var/lib/tomcat9/webapps/ROOT/static/.helper.jsp`.
   - Verify: `! test -f /var/lib/tomcat9/webapps/ROOT/static/.helper.jsp`
   - Risk: service

## P2 — Harden
7. upgrade log4j past 2.15 and disable JNDI lookups — target: `/opt/app/log4j2.xml`.
   - Verify: `grep -L 'log4j-core-2.1[0-4]' /opt/app/log4j2.xml`
   - Risk: service

## P3 — Rotate
8. rotate application and service-account credentials.
   - Verify: `credential rotation timestamp is recent`
   - Risk: auth

## P4 — Verify
9. confirm the exploit path no longer returns a shell.
   - Verify: `replay a benign JNDI probe and confirm it is refused`
   - Risk: service
10. restart the web service and confirm health.
   - Verify: `systemctl is-active tomcat9 and HTTP 200 on /`
   - Risk: service
RK_ORACLE_EOF
