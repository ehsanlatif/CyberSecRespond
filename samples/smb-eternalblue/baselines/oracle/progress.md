# Progress

Investigation timeline for `smb-eternalblue`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1210 — SMBv1 exploitation (CVE-2017-0144); step 2 T1059.001 — PowerShell execution (after step 1); step 3 T1003.001 — LSASS credential dump (after step 2); step 4 T1486 — ransomware encryption (after step 2); step 5 T1546.003 — WMI event subscription (after step 2); step 6 T1574.001 — DLL search-order hijack (after step 2); step 7 T1070.001 — System event log clear (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
