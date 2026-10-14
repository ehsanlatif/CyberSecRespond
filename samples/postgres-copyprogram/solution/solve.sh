#!/usr/bin/env bash
# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.
set -euo pipefail
OUT="${OUTPUT_PATH:-/app}"
mkdir -p "$OUT"
cat > "$OUT/progress.md" <<'RK_ORACLE_EOF'
# Progress

Investigation timeline for `postgres-copyprogram`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1078 — valid accounts (weak postgres superuser); step 2 T1059.004 — COPY TO PROGRAM shell execution (after step 1); step 3 T1048.003 — DNS-tunnel exfiltration (after step 2); step 4 T1053.003 — cron persistence (after step 2); step 5 T1543.002 — systemd persistence (after step 2); step 6 T1070.006 — timestomp dropped files (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
RK_ORACLE_EOF
cat > "$OUT/intrusion-report.md" <<'RK_ORACLE_EOF'
# Intrusion Report

## Entry Point
valid accounts (weak postgres superuser) (T1078); COPY TO PROGRAM shell execution (T1059.004); DNS-tunnel exfiltration (T1048.003). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| dropper (postgres, daemon) | `/var/lib/pgsql/.local/pgdaemon` | T1059.004 |
| dns-tunnel-config (dns, tunnel) | `/etc/pgdaemon.conf` | T1048.003 |
| timestomp-residue (timestomp, mtime) | `/var/lib/pgsql/.local/.timestamps` | T1070.006 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| cron (pgdaemon, cron) | `/var/spool/cron/postgres` | T1053.003 | yes |
| systemd (pgdaemon, ExecStart) | `/etc/systemd/system/pg-metrics.service` | T1543.002 | **no** |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1078 → T1059.004 → {T1048.003, T1053.003, T1543.002, T1070.006}

- T1078 → T1059.004
- T1059.004 → T1048.003
- T1059.004 → T1053.003
- T1059.004 → T1543.002
- T1059.004 → T1070.006
RK_ORACLE_EOF
cat > "$OUT/vuln-report.md" <<'RK_ORACLE_EOF'
# Vulnerability Report

No CVE-driven entry vector was identified. The vulnerability scan returned an empty finding
set (`/sas/vulns.json`), and disk evidence attributes initial access to weak-credential and
configuration weaknesses rather than exploitation of a software vulnerability.

Confidence: high. Evidence: `/var/lib/pgsql/data/pg_hba.conf`, empty `/sas/vulns.json`.
RK_ORACLE_EOF
cat > "$OUT/baseline-report.md" <<'RK_ORACLE_EOF'
# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| postgres-baseline (trust, 0.0.0.0/0) | `/var/lib/pgsql/data/pg_hba.conf` | BAS-01 |
RK_ORACLE_EOF
cat > "$OUT/remediation-plan.md" <<'RK_ORACLE_EOF'
# Remediation Plan

## P0 — Contain
1. block the DNS-tunnel resolver and attacker IP at the egress firewall.
   - Verify: `outbound DNS to the tunnel domain is blocked`
   - Risk: network

## P1 — Eradicate
2. quarantine the pgdaemon dropper and terminate the process — target: `/var/lib/pgsql/.local/pgdaemon`.
   - Verify: `pgrep -f pgdaemon returns empty`
   - Risk: runtime
3. remove the postgres cron entry — target: `/var/spool/cron/postgres`.
   - Verify: `! test -f /var/spool/cron/postgres`
   - Risk: runtime
4. remove the DNS-tunnel configuration — target: `/etc/pgdaemon.conf`.
   - Verify: `! test -f /etc/pgdaemon.conf`
   - Risk: runtime
5. disable and remove the pg-metrics systemd unit — target: `/etc/systemd/system/pg-metrics.service`.
   - Verify: `systemctl is-enabled pg-metrics returns not enabled`
   - Risk: service

## P2 — Harden
6. set scram-sha-256 auth in pg_hba.conf and restrict listen_addresses — target: `/var/lib/pgsql/data/pg_hba.conf`.
   - Verify: `pg_hba.conf has no trust lines and listen is localhost`
   - Risk: service

## P3 — Rotate
7. rotate the postgres superuser password and app DB credentials.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. confirm COPY TO PROGRAM is no longer reachable by unprivileged roles.
   - Verify: `COPY PROGRAM probe is denied`
   - Risk: service
9. restart postgresql and confirm database health.
   - Verify: `systemctl is-active postgresql and a test query succeeds`
   - Risk: service
RK_ORACLE_EOF
