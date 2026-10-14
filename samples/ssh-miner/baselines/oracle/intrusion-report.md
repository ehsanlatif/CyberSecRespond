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
