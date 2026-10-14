# Progress

Investigation timeline for `ssh-miner`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1110 — SSH brute force as root; step 2 T1021.004 — SSH login (after step 1); step 3 T1059.004 — shell execution (after step 2); step 4 T1496 — cryptomining (after step 3); step 5 T1053.003 — cron persistence (after step 3); step 6 T1546.004 — bashrc persistence (after step 3); step 7 T1543.002 — systemd persistence (after step 3); step 8 T1070.002 — auth log cleared (after step 3).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
