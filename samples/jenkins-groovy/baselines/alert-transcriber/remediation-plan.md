# Remediation Plan

## P1 — Eradicate
1. quarantine the xmrig miner and terminate the process — target: `/opt/jenkins/.xmr/xmrig`.
   - Verify: `pgrep -f xmrig returns empty`
   - Risk: runtime
2. remove the jenkins cron entry — target: `/var/spool/cron/crontabs/jenkins`.
   - Verify: `! test -f /var/spool/cron/crontabs/jenkins`
   - Risk: runtime

## P2 — Harden
3. upgrade Jenkins past the CVE-2024-23897 fix and enable security — target: `/var/lib/jenkins/jobs/.tmp/config.xml`.
   - Verify: `jenkins version is patched and useSecurity=true`
   - Risk: service
