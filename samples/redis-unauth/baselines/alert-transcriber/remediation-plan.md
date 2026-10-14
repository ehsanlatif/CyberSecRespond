# Remediation Plan

## P1 — Eradicate
1. quarantine the miner binary and terminate the process — target: `/tmp/.redis/kdevtmpfsi`.
   - Verify: `pgrep -f kdevtmpfsi returns empty`
   - Risk: runtime
2. remove the injected root cron entry — target: `/var/spool/cron/crontabs/root`.
   - Verify: `grep -c redis /var/spool/cron/crontabs/root == 0`
   - Risk: runtime

## P2 — Harden
3. bind Redis to localhost, enable protected-mode and require auth — target: `/etc/redis/redis.conf`.
   - Verify: `redis-cli CONFIG GET requirepass is set`
   - Risk: service
