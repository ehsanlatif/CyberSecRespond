# Progress

Investigation timeline for `postgres-copyprogram`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1078 — valid accounts (weak postgres superuser); step 2 T1059.004 — COPY TO PROGRAM shell execution (after step 1); step 3 T1048.003 — DNS-tunnel exfiltration (after step 2); step 4 T1053.003 — cron persistence (after step 2); step 5 T1543.002 — systemd persistence (after step 2); step 6 T1070.006 — timestomp dropped files (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
