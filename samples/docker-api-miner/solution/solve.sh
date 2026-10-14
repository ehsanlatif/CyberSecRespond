#!/usr/bin/env bash
# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.
set -euo pipefail
OUT="${OUTPUT_PATH:-/app}"
mkdir -p "$OUT"
cat > "$OUT/progress.md" <<'RK_ORACLE_EOF'
# Progress

Investigation timeline for `docker-api-miner`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1133 — exposed Docker API (external service); step 2 T1610 — deploy privileged container (after step 1); step 3 T1611 — container escape to host (after step 2); step 4 T1496 — cryptomining (after step 3); step 5 T1053.003 — cron persistence (after step 3); step 6 T1543.002 — systemd persistence (after step 3).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
RK_ORACLE_EOF
cat > "$OUT/intrusion-report.md" <<'RK_ORACLE_EOF'
# Intrusion Report

## Entry Point
exposed Docker API (external service) (T1133); deploy privileged container (T1610); container escape to host (T1611). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| miner-process (xmrig, pool) | `/opt/xmrig/xmrig` | T1496 |
| container-residue (entrypoint, curl) | `/var/lib/docker/overlay2/attacker/diff/entrypoint.sh` | T1610 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| cron (xmrig, cron) | `/etc/cron.d/docker-mon` | T1053.003 | yes |
| systemd (xmrig, ExecStart) | `/etc/systemd/system/docker-metrics.service` | T1543.002 | **no** |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1133 → T1610 → T1611 → {T1496, T1053.003, T1543.002}

- T1133 → T1610
- T1610 → T1611
- T1611 → T1496
- T1611 → T1053.003
- T1611 → T1543.002
RK_ORACLE_EOF
cat > "$OUT/vuln-report.md" <<'RK_ORACLE_EOF'
# Vulnerability Report

No CVE-driven entry vector was identified. The vulnerability scan returned an empty finding
set (`/sas/vulns.json`), and disk evidence attributes initial access to weak-credential and
configuration weaknesses rather than exploitation of a software vulnerability.

Confidence: high. Evidence: `/etc/docker/daemon.json`, empty `/sas/vulns.json`.
RK_ORACLE_EOF
cat > "$OUT/baseline-report.md" <<'RK_ORACLE_EOF'
# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| docker-baseline (2375, hosts) | `/etc/docker/daemon.json` | BAS-01 |
RK_ORACLE_EOF
cat > "$OUT/remediation-plan.md" <<'RK_ORACLE_EOF'
# Remediation Plan

## P0 — Contain
1. firewall the Docker API port and block the attacker IP.
   - Verify: `port 2375 is not reachable off-host`
   - Risk: network

## P1 — Eradicate
2. quarantine the xmrig miner and terminate the process — target: `/opt/xmrig/xmrig`.
   - Verify: `pgrep -f xmrig returns empty`
   - Risk: runtime
3. remove the docker-mon cron entry — target: `/etc/cron.d/docker-mon`.
   - Verify: `! test -f /etc/cron.d/docker-mon`
   - Risk: runtime
4. disable and remove the docker-metrics systemd unit — target: `/etc/systemd/system/docker-metrics.service`.
   - Verify: `systemctl is-enabled docker-metrics returns not enabled`
   - Risk: service
5. stop and remove the attacker container and image — target: `/var/lib/docker/overlay2/attacker/diff/entrypoint.sh`.
   - Verify: `docker ps -a shows no attacker container`
   - Risk: service

## P2 — Harden
6. disable the TCP Docker socket; require TLS/localhost only — target: `/etc/docker/daemon.json`.
   - Verify: `daemon.json exposes no 0.0.0.0:2375 host`
   - Risk: service

## P3 — Rotate
7. rotate credentials and secrets reachable from the host and containers.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. restart Docker with the hardened config and confirm host health.
   - Verify: `systemctl is-active docker and CPU baseline normal`
   - Risk: service
RK_ORACLE_EOF
