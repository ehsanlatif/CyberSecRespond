# Remediation Plan

## P1 — Eradicate
1. quarantine the JSP webshell and remove the drop directory — target: `/var/lib/tomcat9/webapps/ROOT/static/status.jsp`.
   - Verify: `! test -f /var/lib/tomcat9/webapps/ROOT/static/status.jsp`
   - Risk: service
2. terminate the reverse-shell process — target: `/tmp/.sysd`.
   - Verify: `pgrep -f .sysd returns empty`
   - Risk: runtime
3. disable and remove apache-cache.service — target: `/etc/systemd/system/apache-cache.service`.
   - Verify: `systemctl is-enabled apache-cache 2>&1 | grep -qv enabled`
   - Risk: service

## P2 — Harden
4. upgrade log4j past 2.15 and disable JNDI lookups — target: `/opt/app/log4j2.xml`.
   - Verify: `grep -L 'log4j-core-2.1[0-4]' /opt/app/log4j2.xml`
   - Risk: service
