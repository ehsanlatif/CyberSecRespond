# Intrusion Report

## Entry Point
Struts2 OGNL RCE (CVE-2023-50164) (T1190); JSP webshell planted (T1505.003); shell execution (T1059.004). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| exfil-archive (tar, dump) | `/tmp/.cache/dump.tar.gz` | T1560.001 |
| exfil-endpoint (POST, exfil) | `/var/log/tomcat/access-exfil.log` | T1048 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| ssh-key-backdoor (ssh-ed25519, attacker) | `/root/.ssh/authorized_keys` | T1098.004 | **no** |
| cron (curl, beacon) | `/var/spool/cron/tomcat` | T1053.003 | yes |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1190 → T1505.003 → T1059.004 → {T1560.001, T1098.004, T1053.003, T1070.002}

- T1190 → T1505.003
- T1505.003 → T1059.004
- T1059.004 → T1560.001
- T1560.001 → T1048
- T1059.004 → T1098.004
- T1059.004 → T1053.003
- T1059.004 → T1070.002
