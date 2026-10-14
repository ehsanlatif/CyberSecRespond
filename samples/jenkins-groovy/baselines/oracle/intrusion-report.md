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
