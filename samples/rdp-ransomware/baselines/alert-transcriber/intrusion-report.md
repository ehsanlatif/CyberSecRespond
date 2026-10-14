# Intrusion Report

## Entry Point
RDP brute force (T1110); RDP logon (T1021.001); PowerShell execution (T1059.001). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| ransomware-binary (encrypt, locked) | `/Users/Public/svc.exe` | T1486 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| scheduled-task (schtasks, svc.exe) | `/Windows/System32/Tasks/UpdateHelper` | T1053.005 | yes |
| malicious-service (service, helper) | `/Windows/System32/svc-helper.sys` | T1543.003 | yes |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1110 → T1021.001 → T1059.001 → {T1486, T1053.005, T1547.001, T1543.003, T1070.001}

- T1110 → T1021.001
- T1021.001 → T1059.001
- T1059.001 → T1486
- T1059.001 → T1053.005
- T1059.001 → T1547.001
- T1059.001 → T1543.003
- T1059.001 → T1070.001
