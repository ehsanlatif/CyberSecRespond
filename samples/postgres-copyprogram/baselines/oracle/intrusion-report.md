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
