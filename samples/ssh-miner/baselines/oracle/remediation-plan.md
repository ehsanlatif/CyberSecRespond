# Remediation Plan

## P0 — Contain
1. block attacker source IP inbound.
   - Verify: `iptables -L INPUT -n | grep <ip>`
   - Risk: network

## P1 — Eradicate
2. quarantine miner binary and terminate the process — target: `/tmp/.X11-unix/.xorg`.
   - Verify: `pgrep -f .xorg returns empty`
   - Risk: runtime
3. remove cron entry from /var/spool/cron/root — target: `/var/spool/cron/root`.
   - Verify: `grep -c '<marker>' /var/spool/cron/root == 0`
   - Risk: runtime
4. remove injected line from /root/.bashrc — target: `/root/.bashrc`.
   - Verify: `grep -c '<marker>' /root/.bashrc == 0`
   - Risk: runtime
5. disable and remove system-update-helper.service — target: `/etc/systemd/system/system-update-helper.service`.
   - Verify: `systemctl is-enabled system-update-helper 2>&1 | grep -qv enabled`
   - Risk: service
6. remove /etc/sudoers.d/devops NOPASSWD grant — target: `/etc/sudoers.d/devops`.
   - Verify: `! grep -q NOPASSWD /etc/sudoers.d/devops`
   - Risk: auth

## P2 — Harden
7. set PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 3; reload sshd — target: `/etc/ssh/sshd_config`.
   - Verify: `sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries'`
   - Risk: auth
8. bind MySQL to localhost and revoke the remote root grant — target: `/etc/my.cnf`.
   - Verify: `grep -q '^bind-address' /etc/my.cnf`
   - Risk: service

## P3 — Rotate
9. rotate root and devops credentials.
   - Verify: `chage -l root shows a recent change date`
   - Risk: auth

## P4 — Verify
10. confirm sshd hardening took effect.
   - Verify: `sshd -T | grep permitrootlogin`
   - Risk: auth
11. restart affected services and confirm health.
   - Verify: `systemctl is-active <svc> and HTTP 200 on /`
   - Risk: service
