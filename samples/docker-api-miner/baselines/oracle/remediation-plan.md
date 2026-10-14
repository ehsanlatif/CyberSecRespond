# Remediation Plan

## P0 — Contain
1. firewall the Docker API port and block the attacker IP.
   - Verify: `port 2375 is not reachable off-host`
   - Risk: network

## P1 — Eradicate
2. quarantine the xmrig miner and terminate the process — target: `/opt/xmrig/xmrig`.
   - Verify: `pgrep -f xmrig returns empty`
   - Risk: runtime
3. remove the docker-mon cron entry — target: `/etc/cron.d/docker-mon`.
   - Verify: `! test -f /etc/cron.d/docker-mon`
   - Risk: runtime
4. disable and remove the docker-metrics systemd unit — target: `/etc/systemd/system/docker-metrics.service`.
   - Verify: `systemctl is-enabled docker-metrics returns not enabled`
   - Risk: service
5. stop and remove the attacker container and image — target: `/var/lib/docker/overlay2/attacker/diff/entrypoint.sh`.
   - Verify: `docker ps -a shows no attacker container`
   - Risk: service

## P2 — Harden
6. disable the TCP Docker socket; require TLS/localhost only — target: `/etc/docker/daemon.json`.
   - Verify: `daemon.json exposes no 0.0.0.0:2375 host`
   - Risk: service

## P3 — Rotate
7. rotate credentials and secrets reachable from the host and containers.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. restart Docker with the hardened config and confirm host health.
   - Verify: `systemctl is-active docker and CPU baseline normal`
   - Risk: service
