# Intrusion Report

## Entry Point
Log4Shell RCE (CVE-2021-44228) (T1190); JSP webshell planted (T1505.003); reverse shell execution (T1059.004). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| reverse-shell (process, reverse, bash -i) | `/tmp/.sysd` | T1059.004 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| systemd | `/etc/systemd/system/apache-cache.service` | T1543.002 | yes |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1190 → T1505.003 → {T1059.004, T1070.006}

- T1190 → T1505.003
- T1505.003 → T1059.004
- T1059.004 → T1053.003
- T1059.004 → T1543.002
- T1505.003 → T1070.006
