# Remediation Plan

## P1 — Eradicate
1. quarantine upload.jsp and its drop directory — target: `/opt/tomcat/webapps/ROOT/static/upload.jsp`.
   - Verify: `! test -f /opt/tomcat/webapps/ROOT/static/upload.jsp`
   - Risk: service
2. remove the staged exfil archive — target: `/tmp/.cache/dump.tar.gz`.
   - Verify: `! test -f /tmp/.cache/dump.tar.gz`
   - Risk: runtime
3. remove the tomcat cron entry — target: `/var/spool/cron/tomcat`.
   - Verify: `! test -f /var/spool/cron/tomcat`
   - Risk: runtime

## P2 — Harden
4. upgrade struts2 past the fixed release — target: `/opt/tomcat/lib/struts2-core.jar`.
   - Verify: `rpm -q struts2 shows a patched version`
   - Risk: service
