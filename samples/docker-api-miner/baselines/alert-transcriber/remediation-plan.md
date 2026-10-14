# Remediation Plan

## P1 — Eradicate
1. quarantine the xmrig miner and terminate the process — target: `/opt/xmrig/xmrig`.
   - Verify: `pgrep -f xmrig returns empty`
   - Risk: runtime
2. remove the docker-mon cron entry — target: `/etc/cron.d/docker-mon`.
   - Verify: `! test -f /etc/cron.d/docker-mon`
   - Risk: runtime

## P2 — Harden
3. disable the TCP Docker socket; require TLS/localhost only — target: `/etc/docker/daemon.json`.
   - Verify: `daemon.json exposes no 0.0.0.0:2375 host`
   - Risk: service
