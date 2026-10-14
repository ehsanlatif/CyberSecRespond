# Progress

Investigation timeline for `rdp-ransomware`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1110 — RDP brute force; step 2 T1021.001 — RDP logon (after step 1); step 3 T1059.001 — PowerShell execution (after step 2); step 4 T1486 — ransomware encryption (after step 3); step 5 T1053.005 — scheduled task persistence (after step 3); step 6 T1547.001 — Run key persistence (after step 3); step 7 T1543.003 — malicious service (after step 3); step 8 T1070.001 — Windows event log clear (after step 3).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
