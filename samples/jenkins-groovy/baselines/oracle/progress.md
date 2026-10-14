# Progress

Investigation timeline for `jenkins-groovy`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1190 — Jenkins RCE (CVE-2024-23897); step 2 T1059.004 — Groovy/shell execution (after step 1); step 3 T1496 — cryptomining (after step 2); step 4 T1037.004 — Groovy init hook (after step 2); step 5 T1098.004 — authorized_keys backdoor (after step 2); step 6 T1053.003 — cron persistence (after step 2); step 7 T1070.002 — Jenkins log truncation (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
