# Remediation Plan

## P1 — Eradicate
1. quarantine miner binary and terminate the process — target: `/tmp/.X11-unix/.xorg`.
   - Verify: `pgrep -f .xorg returns empty`
   - Risk: runtime
2. remove cron entry from /var/spool/cron/root — target: `/var/spool/cron/root`.
   - Verify: `grep -c '<marker>' /var/spool/cron/root == 0`
   - Risk: runtime
3. disable and remove system-update-helper.service — target: `/etc/systemd/system/system-update-helper.service`.
   - Verify: `systemctl is-enabled system-update-helper 2>&1 | grep -qv enabled`
   - Risk: service

## P2 — Harden
4. set PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 3; reload sshd — target: `/etc/ssh/sshd_config`.
   - Verify: `sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries'`
   - Risk: auth
5. bind MySQL to localhost and revoke the remote root grant — target: `/etc/my.cnf`.
   - Verify: `grep -q '^bind-address' /etc/my.cnf`
   - Risk: service
