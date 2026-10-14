#!/usr/bin/env bash
# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.
set -euo pipefail
OUT="${OUTPUT_PATH:-/app}"
mkdir -p "$OUT"
cat > "$OUT/progress.md" <<'RK_ORACLE_EOF'
# Progress

Investigation timeline for `jenkins-groovy`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1190 — Jenkins RCE (CVE-2024-23897); step 2 T1059.004 — Groovy/shell execution (after step 1); step 3 T1496 — cryptomining (after step 2); step 4 T1037.004 — Groovy init hook (after step 2); step 5 T1098.004 — authorized_keys backdoor (after step 2); step 6 T1053.003 — cron persistence (after step 2); step 7 T1070.002 — Jenkins log truncation (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
RK_ORACLE_EOF
cat > "$OUT/intrusion-report.md" <<'RK_ORACLE_EOF'
# Intrusion Report

## Entry Point
Jenkins RCE (CVE-2024-23897) (T1190); Groovy/shell execution (T1059.004); cryptomining (T1496). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| miner-process (xmrig, pool) | `/opt/jenkins/.xmr/xmrig` | T1496 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| groovy-init-hook (Thread, execute) | `/var/lib/jenkins/init.groovy.d/z-backdoor.groovy` | T1037.004 | **no** |
| ssh-key-backdoor (ssh-rsa, attacker) | `/var/lib/jenkins/.ssh/authorized_keys` | T1098.004 | **no** |
| cron (xmrig, cron) | `/var/spool/cron/crontabs/jenkins` | T1053.003 | yes |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1190 → T1059.004 → {T1496, T1037.004, T1098.004, T1053.003, T1070.002}

- T1190 → T1059.004
- T1059.004 → T1496
- T1059.004 → T1037.004
- T1059.004 → T1098.004
- T1059.004 → T1053.003
- T1059.004 → T1070.002
RK_ORACLE_EOF
cat > "$OUT/vuln-report.md" <<'RK_ORACLE_EOF'
# Vulnerability Report

A CVE-driven entry vector was identified:

- CVE-2024-23897 — `/var/lib/jenkins/jobs/.tmp/config.xml` (rce-artifact (jenkins, @))

Confidence: high. Evidence cited inline.
RK_ORACLE_EOF
cat > "$OUT/baseline-report.md" <<'RK_ORACLE_EOF'
# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| jenkins-baseline (useSecurity, false) | `/var/lib/jenkins/config.xml` | BAS-01 |
RK_ORACLE_EOF
cat > "$OUT/remediation-plan.md" <<'RK_ORACLE_EOF'
# Remediation Plan

## P0 — Contain
1. block the mining pool and attacker IP at the egress firewall.
   - Verify: `iptables -L OUTPUT -n | grep <pool-ip>`
   - Risk: network

## P1 — Eradicate
2. quarantine the xmrig miner and terminate the process — target: `/opt/jenkins/.xmr/xmrig`.
   - Verify: `pgrep -f xmrig returns empty`
   - Risk: runtime
3. remove the malicious Groovy init hook — target: `/var/lib/jenkins/init.groovy.d/z-backdoor.groovy`.
   - Verify: `! test -f /var/lib/jenkins/init.groovy.d/z-backdoor.groovy`
   - Risk: service
4. remove the attacker key from the jenkins authorized_keys — target: `/var/lib/jenkins/.ssh/authorized_keys`.
   - Verify: `! grep -q attacker /var/lib/jenkins/.ssh/authorized_keys`
   - Risk: auth
5. remove the jenkins cron entry — target: `/var/spool/cron/crontabs/jenkins`.
   - Verify: `! test -f /var/spool/cron/crontabs/jenkins`
   - Risk: runtime

## P2 — Harden
6. upgrade Jenkins past the CVE-2024-23897 fix and enable security — target: `/var/lib/jenkins/jobs/.tmp/config.xml`.
   - Verify: `jenkins version is patched and useSecurity=true`
   - Risk: service

## P3 — Rotate
7. rotate Jenkins admin, agent, and stored pipeline credentials.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. confirm the CVE-2024-23897 path no longer discloses files.
   - Verify: `benign probe returns access denied`
   - Risk: service
9. restart Jenkins and confirm controller health.
   - Verify: `systemctl is-active jenkins and HTTP 200 on /login`
   - Risk: service
RK_ORACLE_EOF
