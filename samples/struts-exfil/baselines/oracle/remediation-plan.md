# Remediation Plan

## P0 — Contain
1. block the exfil destination and attacker IP at the egress firewall.
   - Verify: `iptables -L OUTPUT -n | grep <ip>`
   - Risk: network

## P1 — Eradicate
2. quarantine upload.jsp and its drop directory — target: `/opt/tomcat/webapps/ROOT/static/upload.jsp`.
   - Verify: `! test -f /opt/tomcat/webapps/ROOT/static/upload.jsp`
   - Risk: service
3. remove the staged exfil archive — target: `/tmp/.cache/dump.tar.gz`.
   - Verify: `! test -f /tmp/.cache/dump.tar.gz`
   - Risk: runtime
4. remove the attacker key from /root/.ssh/authorized_keys — target: `/root/.ssh/authorized_keys`.
   - Verify: `! grep -q attacker /root/.ssh/authorized_keys`
   - Risk: auth
5. remove the tomcat cron entry — target: `/var/spool/cron/tomcat`.
   - Verify: `! test -f /var/spool/cron/tomcat`
   - Risk: runtime

## P2 — Harden
6. upgrade struts2 past the fixed release — target: `/opt/tomcat/lib/struts2-core.jar`.
   - Verify: `rpm -q struts2 shows a patched version`
   - Risk: service

## P3 — Rotate
7. rotate application, root, and any exfiltrated credentials.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. confirm the OGNL exploit path no longer executes.
   - Verify: `replay a benign probe and confirm it is rejected`
   - Risk: service
9. restart tomcat and confirm service health.
   - Verify: `systemctl is-active tomcat and HTTP 200 on /`
   - Risk: service
