# Progress

Investigation timeline for `log4shell-webshell`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1190 — Log4Shell RCE (CVE-2021-44228); step 2 T1505.003 — JSP webshell planted (after step 1); step 3 T1059.004 — reverse shell execution (after step 2); step 4 T1053.003 — cron persistence (after step 3); step 5 T1543.002 — systemd persistence (after step 3); step 6 T1070.006 — timestomp webshell (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
