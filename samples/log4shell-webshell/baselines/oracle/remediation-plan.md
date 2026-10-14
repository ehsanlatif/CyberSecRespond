# Remediation Plan

## P0 — Contain
1. block attacker source IP inbound at the edge.
   - Verify: `iptables -L INPUT -n | grep <ip>`
   - Risk: network

## P1 — Eradicate
2. quarantine the JSP webshell and remove the drop directory — target: `/var/lib/tomcat9/webapps/ROOT/static/status.jsp`.
   - Verify: `! test -f /var/lib/tomcat9/webapps/ROOT/static/status.jsp`
   - Risk: service
3. terminate the reverse-shell process — target: `/tmp/.sysd`.
   - Verify: `pgrep -f .sysd returns empty`
   - Risk: runtime
4. remove /etc/cron.d/apache-cache — target: `/etc/cron.d/apache-cache`.
   - Verify: `! test -f /etc/cron.d/apache-cache`
   - Risk: runtime
5. disable and remove apache-cache.service — target: `/etc/systemd/system/apache-cache.service`.
   - Verify: `systemctl is-enabled apache-cache 2>&1 | grep -qv enabled`
   - Risk: service
6. remove the secondary .helper.jsp webshell — target: `/var/lib/tomcat9/webapps/ROOT/static/.helper.jsp`.
   - Verify: `! test -f /var/lib/tomcat9/webapps/ROOT/static/.helper.jsp`
   - Risk: service

## P2 — Harden
7. upgrade log4j past 2.15 and disable JNDI lookups — target: `/opt/app/log4j2.xml`.
   - Verify: `grep -L 'log4j-core-2.1[0-4]' /opt/app/log4j2.xml`
   - Risk: service

## P3 — Rotate
8. rotate application and service-account credentials.
   - Verify: `credential rotation timestamp is recent`
   - Risk: auth

## P4 — Verify
9. confirm the exploit path no longer returns a shell.
   - Verify: `replay a benign JNDI probe and confirm it is refused`
   - Risk: service
10. restart the web service and confirm health.
   - Verify: `systemctl is-active tomcat9 and HTTP 200 on /`
   - Risk: service
