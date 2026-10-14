# Remediation Plan

## P0 — Contain
1. block the DNS-tunnel resolver and attacker IP at the egress firewall.
   - Verify: `outbound DNS to the tunnel domain is blocked`
   - Risk: network

## P1 — Eradicate
2. quarantine the pgdaemon dropper and terminate the process — target: `/var/lib/pgsql/.local/pgdaemon`.
   - Verify: `pgrep -f pgdaemon returns empty`
   - Risk: runtime
3. remove the postgres cron entry — target: `/var/spool/cron/postgres`.
   - Verify: `! test -f /var/spool/cron/postgres`
   - Risk: runtime
4. remove the DNS-tunnel configuration — target: `/etc/pgdaemon.conf`.
   - Verify: `! test -f /etc/pgdaemon.conf`
   - Risk: runtime
5. disable and remove the pg-metrics systemd unit — target: `/etc/systemd/system/pg-metrics.service`.
   - Verify: `systemctl is-enabled pg-metrics returns not enabled`
   - Risk: service

## P2 — Harden
6. set scram-sha-256 auth in pg_hba.conf and restrict listen_addresses — target: `/var/lib/pgsql/data/pg_hba.conf`.
   - Verify: `pg_hba.conf has no trust lines and listen is localhost`
   - Risk: service

## P3 — Rotate
7. rotate the postgres superuser password and app DB credentials.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. confirm COPY TO PROGRAM is no longer reachable by unprivileged roles.
   - Verify: `COPY PROGRAM probe is denied`
   - Risk: service
9. restart postgresql and confirm database health.
   - Verify: `systemctl is-active postgresql and a test query succeeds`
   - Risk: service
