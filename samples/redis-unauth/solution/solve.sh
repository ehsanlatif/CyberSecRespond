#!/usr/bin/env bash
# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.
set -euo pipefail
OUT="${OUTPUT_PATH:-/app}"
mkdir -p "$OUT"
cat > "$OUT/progress.md" <<'RK_ORACLE_EOF'
# Progress

Investigation timeline for `redis-unauth`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1133 — unauthenticated Redis access (external service); step 2 T1059.004 — shell execution via CONFIG SET (after step 1); step 3 T1496 — cryptomining (after step 2); step 4 T1053.003 — cron persistence (after step 2); step 5 T1574.006 — LD_PRELOAD hijack (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
RK_ORACLE_EOF
cat > "$OUT/intrusion-report.md" <<'RK_ORACLE_EOF'
# Intrusion Report

## Entry Point
unauthenticated Redis access (external service) (T1133); shell execution via CONFIG SET (T1059.004); cryptomining (T1496). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| miner-process (miner, pool) | `/tmp/.redis/kdevtmpfsi` | T1496 |
| loadable-module (module, exp.so) | `/tmp/.redis/exp.so` | T1059.004 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| cron (curl, redis) | `/var/spool/cron/crontabs/root` | T1053.003 | yes |
| ld-preload-hook (preload, .so) | `/etc/ld.so.preload` | T1574.006 | **no** |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1133 → T1059.004 → {T1496, T1053.003, T1574.006}

- T1133 → T1059.004
- T1059.004 → T1496
- T1059.004 → T1053.003
- T1059.004 → T1574.006
RK_ORACLE_EOF
cat > "$OUT/vuln-report.md" <<'RK_ORACLE_EOF'
# Vulnerability Report

No CVE-driven entry vector was identified. The vulnerability scan returned an empty finding
set (`/sas/vulns.json`), and disk evidence attributes initial access to weak-credential and
configuration weaknesses rather than exploitation of a software vulnerability.

Confidence: high. Evidence: `/etc/redis/redis.conf`, empty `/sas/vulns.json`.
RK_ORACLE_EOF
cat > "$OUT/baseline-report.md" <<'RK_ORACLE_EOF'
# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| redis-baseline (0.0.0.0, protected-mode) | `/etc/redis/redis.conf` | BAS-01 |
RK_ORACLE_EOF
cat > "$OUT/remediation-plan.md" <<'RK_ORACLE_EOF'
# Remediation Plan

## P0 — Contain
1. firewall the Redis port to localhost and block the attacker IP.
   - Verify: `ss -ltn shows redis bound to 127.0.0.1 only`
   - Risk: network

## P1 — Eradicate
2. quarantine the miner binary and terminate the process — target: `/tmp/.redis/kdevtmpfsi`.
   - Verify: `pgrep -f kdevtmpfsi returns empty`
   - Risk: runtime
3. remove the injected root cron entry — target: `/var/spool/cron/crontabs/root`.
   - Verify: `grep -c redis /var/spool/cron/crontabs/root == 0`
   - Risk: runtime
4. remove the LD_PRELOAD hook from /etc/ld.so.preload — target: `/etc/ld.so.preload`.
   - Verify: `! test -s /etc/ld.so.preload`
   - Risk: runtime
5. remove the attacker Redis module — target: `/tmp/.redis/exp.so`.
   - Verify: `! test -f /tmp/.redis/exp.so`
   - Risk: runtime

## P2 — Harden
6. bind Redis to localhost, enable protected-mode and require auth — target: `/etc/redis/redis.conf`.
   - Verify: `redis-cli CONFIG GET requirepass is set`
   - Risk: service

## P3 — Rotate
7. rotate any credentials reachable from the compromised host.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. restart redis and confirm the host has no miner activity.
   - Verify: `systemctl is-active redis and CPU baseline normal`
   - Risk: service
RK_ORACLE_EOF
