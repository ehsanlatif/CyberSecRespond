# Intrusion Report

## Entry Point
SMBv1 exploitation (CVE-2017-0144) (T1210); PowerShell execution (T1059.001); LSASS credential dump (T1003.001). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| credential-dump (lsass, dump) | `/Windows/Temp/lsass.dmp` | T1003.001 |
| ransomware-binary (encrypt, ransom) | `/Users/Public/enc.exe` | T1486 |

## Persistence Mechanisms
_None identified._

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1210 → T1059.001 → {T1003.001, T1486, T1546.003, T1574.001, T1070.001}

- T1210 → T1059.001
- T1059.001 → T1003.001
- T1059.001 → T1486
- T1059.001 → T1546.003
- T1059.001 → T1574.001
- T1059.001 → T1070.001
