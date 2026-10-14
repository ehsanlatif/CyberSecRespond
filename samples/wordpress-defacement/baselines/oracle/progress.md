# Progress

Investigation timeline for `wordpress-defacement`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1190 — WordPress plugin RCE (CVE-2022-1609); step 2 T1505.003 — PHP webshell planted (after step 1); step 3 T1491.001 — site defacement (after step 2); step 4 T1053.003 — cron persistence (after step 2); step 5 T1505.003 — .htaccess redirect (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
