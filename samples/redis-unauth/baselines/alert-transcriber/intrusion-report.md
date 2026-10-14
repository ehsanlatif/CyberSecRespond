# Intrusion Report

## Entry Point
unauthenticated Redis access (external service) (T1133); shell execution via CONFIG SET (T1059.004); cryptomining (T1496). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| miner-process (miner, pool) | `/tmp/.redis/kdevtmpfsi` | T1496 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| cron (curl, redis) | `/var/spool/cron/crontabs/root` | T1053.003 | yes |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1133 → T1059.004 → {T1496, T1053.003, T1574.006}

- T1133 → T1059.004
- T1059.004 → T1496
- T1059.004 → T1053.003
- T1059.004 → T1574.006
