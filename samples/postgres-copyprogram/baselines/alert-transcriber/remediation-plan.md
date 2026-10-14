# Remediation Plan

## P1 — Eradicate
1. quarantine the pgdaemon dropper and terminate the process — target: `/var/lib/pgsql/.local/pgdaemon`.
   - Verify: `pgrep -f pgdaemon returns empty`
   - Risk: runtime
2. remove the postgres cron entry — target: `/var/spool/cron/postgres`.
   - Verify: `! test -f /var/spool/cron/postgres`
   - Risk: runtime

## P2 — Harden
3. set scram-sha-256 auth in pg_hba.conf and restrict listen_addresses — target: `/var/lib/pgsql/data/pg_hba.conf`.
   - Verify: `pg_hba.conf has no trust lines and listen is localhost`
   - Risk: service
