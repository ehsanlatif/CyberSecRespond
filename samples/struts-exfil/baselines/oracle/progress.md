# Progress

Investigation timeline for `struts-exfil`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1190 — Struts2 OGNL RCE (CVE-2023-50164); step 2 T1505.003 — JSP webshell planted (after step 1); step 3 T1059.004 — shell execution (after step 2); step 4 T1560.001 — stage archive for exfil (after step 3); step 5 T1048 — exfiltrate over HTTPS (after step 4); step 6 T1098.004 — authorized_keys backdoor (after step 3); step 7 T1053.003 — cron persistence (after step 3); step 8 T1070.002 — selective auth-log wipe (after step 3).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
