#!/usr/bin/env bash
# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.
set -euo pipefail
OUT="${OUTPUT_PATH:-/app}"
mkdir -p "$OUT"
cat > "$OUT/progress.md" <<'RK_ORACLE_EOF'
# Progress

Investigation timeline for `rdp-ransomware`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1110 — RDP brute force; step 2 T1021.001 — RDP logon (after step 1); step 3 T1059.001 — PowerShell execution (after step 2); step 4 T1486 — ransomware encryption (after step 3); step 5 T1053.005 — scheduled task persistence (after step 3); step 6 T1547.001 — Run key persistence (after step 3); step 7 T1543.003 — malicious service (after step 3); step 8 T1070.001 — Windows event log clear (after step 3).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
RK_ORACLE_EOF
cat > "$OUT/intrusion-report.md" <<'RK_ORACLE_EOF'
# Intrusion Report

## Entry Point
RDP brute force (T1110); RDP logon (T1021.001); PowerShell execution (T1059.001). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| ransomware-binary (encrypt, locked) | `/Users/Public/svc.exe` | T1486 |
| cleared-eventlog (cleared, 1102) | `/Windows/System32/winevt/Logs/Security.evtx` | T1070.001 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| scheduled-task (schtasks, svc.exe) | `/Windows/System32/Tasks/UpdateHelper` | T1053.005 | yes |
| run-key (Run, svc) | `/Windows/System32/config/SOFTWARE` | T1547.001 | **no** |
| malicious-service (service, helper) | `/Windows/System32/svc-helper.sys` | T1543.003 | yes |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1110 → T1021.001 → T1059.001 → {T1486, T1053.005, T1547.001, T1543.003, T1070.001}

- T1110 → T1021.001
- T1021.001 → T1059.001
- T1059.001 → T1486
- T1059.001 → T1053.005
- T1059.001 → T1547.001
- T1059.001 → T1543.003
- T1059.001 → T1070.001
RK_ORACLE_EOF
cat > "$OUT/vuln-report.md" <<'RK_ORACLE_EOF'
# Vulnerability Report

No CVE-driven entry vector was identified. The vulnerability scan returned an empty finding
set (`/sas/vulns.json`), and disk evidence attributes initial access to weak-credential and
configuration weaknesses rather than exploitation of a software vulnerability.

Confidence: high. Evidence: `/Windows/System32/config/RDP-Tcp.reg`, empty `/sas/vulns.json`.
RK_ORACLE_EOF
cat > "$OUT/baseline-report.md" <<'RK_ORACLE_EOF'
# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| rdp-baseline (UserAuthentication, 0) | `/Windows/System32/config/RDP-Tcp.reg` | BAS-01 |
RK_ORACLE_EOF
cat > "$OUT/remediation-plan.md" <<'RK_ORACLE_EOF'
# Remediation Plan

## P0 — Contain
1. isolate the host from the network and block the attacker IP.
   - Verify: `host shows no inbound RDP from <ip>`
   - Risk: network

## P1 — Eradicate
2. quarantine svc.exe and terminate the ransomware process — target: `/Users/Public/svc.exe`.
   - Verify: `no running process references svc.exe`
   - Risk: runtime
3. delete the UpdateHelper scheduled task — target: `/Windows/System32/Tasks/UpdateHelper`.
   - Verify: `schtasks /query has no UpdateHelper`
   - Risk: runtime
4. remove the malicious Run-key value — target: `/Windows/System32/config/SOFTWARE`.
   - Verify: `reg query ...\Run has no svc value`
   - Risk: runtime
5. stop and remove the svc-helper service — target: `/Windows/System32/svc-helper.sys`.
   - Verify: `sc query svc-helper returns not found`
   - Risk: service

## P2 — Harden
6. enable NLA and restrict RDP to VPN/allowlisted sources — target: `/Windows/System32/config/RDP-Tcp.reg`.
   - Verify: `UserAuthentication == 1 and RDP is firewalled`
   - Risk: auth

## P3 — Rotate
7. reset all local and domain credentials used on this host.
   - Verify: `credential reset timestamps are recent`
   - Risk: auth

## P4 — Verify
8. confirm RDP no longer accepts unauthenticated sessions.
   - Verify: `RDP probe is refused without NLA`
   - Risk: auth
9. restore encrypted data from backup and confirm services healthy.
   - Verify: `critical services running and files restored`
   - Risk: service
RK_ORACLE_EOF
