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
