# Progress

Investigation timeline for `docker-api-miner`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1133 — exposed Docker API (external service); step 2 T1610 — deploy privileged container (after step 1); step 3 T1611 — container escape to host (after step 2); step 4 T1496 — cryptomining (after step 3); step 5 T1053.003 — cron persistence (after step 3); step 6 T1543.002 — systemd persistence (after step 3).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
