#!/usr/bin/env bash
# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.
set -euo pipefail
OUT="${OUTPUT_PATH:-/app}"
mkdir -p "$OUT"
cat > "$OUT/progress.md" <<'RK_ORACLE_EOF'
# Progress

Investigation timeline for `ssh-miner`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1110 — SSH brute force as root; step 2 T1021.004 — SSH login (after step 1); step 3 T1059.004 — shell execution (after step 2); step 4 T1496 — cryptomining (after step 3); step 5 T1053.003 — cron persistence (after step 3); step 6 T1546.004 — bashrc persistence (after step 3); step 7 T1543.002 — systemd persistence (after step 3); step 8 T1070.002 — auth log cleared (after step 3).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
RK_ORACLE_EOF
cat > "$OUT/intrusion-report.md" <<'RK_ORACLE_EOF'
# Intrusion Report

## Entry Point
SSH brute force as root (T1110); SSH login (T1021.004); shell execution (T1059.004). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| miner-process (process, pid) | `/tmp/.X11-unix/.xorg` | T1496 |
| miner-binary (binary, hash) | `/tmp/.X11-unix/.xorg` | T1496 |
| attack-tool-residue (hydra, brute) | `/home/devops/.bash_history` | T1110 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| sudoers-backdoor (NOPASSWD) | `/etc/sudoers.d/devops` | T1548.003 | **no** |
| cron | `/var/spool/cron/root` | T1053.003 | yes |
| shell-init | `/root/.bashrc` | T1546.004 | **no** |
| systemd | `/etc/systemd/system/system-update-helper.service` | T1543.002 | yes |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1110 → T1021.004 → T1059.004 → {T1496, T1053.003, T1546.004, T1543.002, T1070.002}

- T1110 → T1021.004
- T1021.004 → T1059.004
- T1059.004 → T1496
- T1059.004 → T1053.003
- T1059.004 → T1546.004
- T1059.004 → T1543.002
- T1059.004 → T1070.002
RK_ORACLE_EOF
cat > "$OUT/vuln-report.md" <<'RK_ORACLE_EOF'
# Vulnerability Report

No CVE-driven entry vector was identified. The vulnerability scan returned an empty finding
set (`/sas/vulns.json`), and disk evidence attributes initial access to weak-credential and
configuration weaknesses rather than exploitation of a software vulnerability.

Confidence: high. Evidence: `/etc/ssh/sshd_config`, `/etc/my.cnf`, empty `/sas/vulns.json`.
RK_ORACLE_EOF
cat > "$OUT/baseline-report.md" <<'RK_ORACLE_EOF'
# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| ssh-baseline (PermitRootLogin) | `/etc/ssh/sshd_config` | BAS-01 |
| mysql-remote-root (bind-address, 0.0.0.0) | `/etc/my.cnf` | BAS-02 |
RK_ORACLE_EOF
cat > "$OUT/remediation-plan.md" <<'RK_ORACLE_EOF'
# Remediation Plan

## P0 — Contain
1. block attacker source IP inbound.
   - Verify: `iptables -L INPUT -n | grep <ip>`
   - Risk: network

## P1 — Eradicate
2. quarantine miner binary and terminate the process — target: `/tmp/.X11-unix/.xorg`.
   - Verify: `pgrep -f .xorg returns empty`
   - Risk: runtime
3. remove cron entry from /var/spool/cron/root — target: `/var/spool/cron/root`.
   - Verify: `grep -c '<marker>' /var/spool/cron/root == 0`
   - Risk: runtime
4. remove injected line from /root/.bashrc — target: `/root/.bashrc`.
   - Verify: `grep -c '<marker>' /root/.bashrc == 0`
   - Risk: runtime
5. disable and remove system-update-helper.service — target: `/etc/systemd/system/system-update-helper.service`.
   - Verify: `systemctl is-enabled system-update-helper 2>&1 | grep -qv enabled`
   - Risk: service
6. remove /etc/sudoers.d/devops NOPASSWD grant — target: `/etc/sudoers.d/devops`.
   - Verify: `! grep -q NOPASSWD /etc/sudoers.d/devops`
   - Risk: auth

## P2 — Harden
7. set PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 3; reload sshd — target: `/etc/ssh/sshd_config`.
   - Verify: `sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries'`
   - Risk: auth
8. bind MySQL to localhost and revoke the remote root grant — target: `/etc/my.cnf`.
   - Verify: `grep -q '^bind-address' /etc/my.cnf`
   - Risk: service

## P3 — Rotate
9. rotate root and devops credentials.
   - Verify: `chage -l root shows a recent change date`
   - Risk: auth

## P4 — Verify
10. confirm sshd hardening took effect.
   - Verify: `sshd -T | grep permitrootlogin`
   - Risk: auth
11. restart affected services and confirm health.
   - Verify: `systemctl is-active <svc> and HTTP 200 on /`
   - Risk: service
RK_ORACLE_EOF
