# Remediation Plan

## P0 — Contain
1. firewall the Redis port to localhost and block the attacker IP.
   - Verify: `ss -ltn shows redis bound to 127.0.0.1 only`
   - Risk: network

## P1 — Eradicate
2. quarantine the miner binary and terminate the process — target: `/tmp/.redis/kdevtmpfsi`.
   - Verify: `pgrep -f kdevtmpfsi returns empty`
   - Risk: runtime
3. remove the injected root cron entry — target: `/var/spool/cron/crontabs/root`.
   - Verify: `grep -c redis /var/spool/cron/crontabs/root == 0`
   - Risk: runtime
4. remove the LD_PRELOAD hook from /etc/ld.so.preload — target: `/etc/ld.so.preload`.
   - Verify: `! test -s /etc/ld.so.preload`
   - Risk: runtime
5. remove the attacker Redis module — target: `/tmp/.redis/exp.so`.
   - Verify: `! test -f /tmp/.redis/exp.so`
   - Risk: runtime

## P2 — Harden
6. bind Redis to localhost, enable protected-mode and require auth — target: `/etc/redis/redis.conf`.
   - Verify: `redis-cli CONFIG GET requirepass is set`
   - Risk: service

## P3 — Rotate
7. rotate any credentials reachable from the compromised host.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. restart redis and confirm the host has no miner activity.
   - Verify: `systemctl is-active redis and CPU baseline normal`
   - Risk: service
