#!/usr/bin/env bash
# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.
set -euo pipefail
OUT="${OUTPUT_PATH:-/app}"
mkdir -p "$OUT"
cat > "$OUT/progress.md" <<'RK_ORACLE_EOF'
# Progress

Investigation timeline for `smb-eternalblue`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1210 — SMBv1 exploitation (CVE-2017-0144); step 2 T1059.001 — PowerShell execution (after step 1); step 3 T1003.001 — LSASS credential dump (after step 2); step 4 T1486 — ransomware encryption (after step 2); step 5 T1546.003 — WMI event subscription (after step 2); step 6 T1574.001 — DLL search-order hijack (after step 2); step 7 T1070.001 — System event log clear (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
RK_ORACLE_EOF
cat > "$OUT/intrusion-report.md" <<'RK_ORACLE_EOF'
# Intrusion Report

## Entry Point
SMBv1 exploitation (CVE-2017-0144) (T1210); PowerShell execution (T1059.001); LSASS credential dump (T1003.001). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| credential-dump (lsass, dump) | `/Windows/Temp/lsass.dmp` | T1003.001 |
| ransomware-binary (encrypt, ransom) | `/Users/Public/enc.exe` | T1486 |
| cleared-eventlog (cleared, 1102) | `/Windows/System32/winevt/Logs/System.evtx` | T1070.001 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| wmi-subscription (EventFilter, CommandLineEventConsumer) | `/Windows/System32/wbem/Repository/OBJECTS.DATA` | T1546.003 | **no** |
| hijacked-dll (hijack, sideload) | `/Windows/System32/wbem/wbemcomn.dll` | T1574.001 | **no** |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1210 → T1059.001 → {T1003.001, T1486, T1546.003, T1574.001, T1070.001}

- T1210 → T1059.001
- T1059.001 → T1003.001
- T1059.001 → T1486
- T1059.001 → T1546.003
- T1059.001 → T1574.001
- T1059.001 → T1070.001
RK_ORACLE_EOF
cat > "$OUT/vuln-report.md" <<'RK_ORACLE_EOF'
# Vulnerability Report

A CVE-driven entry vector was identified:

- CVE-2017-0144 — `/Windows/Temp/mssecsvc.exe` (exploit-implant (smb, doublepulsar))

Confidence: high. Evidence cited inline.
RK_ORACLE_EOF
cat > "$OUT/baseline-report.md" <<'RK_ORACLE_EOF'
# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| smbv1-baseline (SMBv1, MS17-010) | `/Windows/System32/drivers/srv.sys` | BAS-01 |
RK_ORACLE_EOF
cat > "$OUT/remediation-plan.md" <<'RK_ORACLE_EOF'
# Remediation Plan

## P0 — Contain
1. isolate the host and block SMB from untrusted networks.
   - Verify: `port 445 is not reachable from outside the segment`
   - Risk: network

## P1 — Eradicate
2. quarantine the EternalBlue implant — target: `/Windows/Temp/mssecsvc.exe`.
   - Verify: `! test -f /Windows/Temp/mssecsvc.exe`
   - Risk: runtime
3. quarantine the ransomware binary and terminate the process — target: `/Users/Public/enc.exe`.
   - Verify: `no process references enc.exe`
   - Risk: runtime
4. remove the malicious WMI __EventFilter/consumer binding — target: `/Windows/System32/wbem/Repository/OBJECTS.DATA`.
   - Verify: `Get-WmiObject __EventConsumer shows no attacker consumer`
   - Risk: service
5. restore the legitimate wbemcomn.dll and remove the hijack — target: `/Windows/System32/wbem/wbemcomn.dll`.
   - Verify: `signed wbemcomn.dll is in place`
   - Risk: service

## P2 — Harden
6. apply MS17-010 and disable SMBv1 — target: `/Windows/System32/drivers/srv.sys`.
   - Verify: `SMBv1 disabled and patch present`
   - Risk: service

## P3 — Rotate
7. reset all credentials exposed in the LSASS dump (assume domain-wide).
   - Verify: `credential reset timestamps are recent`
   - Risk: auth

## P4 — Verify
8. confirm the SMBv1 exploit path is closed.
   - Verify: `MS17-010 scanner reports not vulnerable`
   - Risk: service
9. restore encrypted data from backup and confirm host health.
   - Verify: `files restored and services running`
   - Risk: service
RK_ORACLE_EOF
