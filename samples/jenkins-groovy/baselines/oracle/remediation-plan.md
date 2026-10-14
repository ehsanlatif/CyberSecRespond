# Remediation Plan

## P0 — Contain
1. block the mining pool and attacker IP at the egress firewall.
   - Verify: `iptables -L OUTPUT -n | grep <pool-ip>`
   - Risk: network

## P1 — Eradicate
2. quarantine the xmrig miner and terminate the process — target: `/opt/jenkins/.xmr/xmrig`.
   - Verify: `pgrep -f xmrig returns empty`
   - Risk: runtime
3. remove the malicious Groovy init hook — target: `/var/lib/jenkins/init.groovy.d/z-backdoor.groovy`.
   - Verify: `! test -f /var/lib/jenkins/init.groovy.d/z-backdoor.groovy`
   - Risk: service
4. remove the attacker key from the jenkins authorized_keys — target: `/var/lib/jenkins/.ssh/authorized_keys`.
   - Verify: `! grep -q attacker /var/lib/jenkins/.ssh/authorized_keys`
   - Risk: auth
5. remove the jenkins cron entry — target: `/var/spool/cron/crontabs/jenkins`.
   - Verify: `! test -f /var/spool/cron/crontabs/jenkins`
   - Risk: runtime

## P2 — Harden
6. upgrade Jenkins past the CVE-2024-23897 fix and enable security — target: `/var/lib/jenkins/jobs/.tmp/config.xml`.
   - Verify: `jenkins version is patched and useSecurity=true`
   - Risk: service

## P3 — Rotate
7. rotate Jenkins admin, agent, and stored pipeline credentials.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. confirm the CVE-2024-23897 path no longer discloses files.
   - Verify: `benign probe returns access denied`
   - Risk: service
9. restart Jenkins and confirm controller health.
   - Verify: `systemctl is-active jenkins and HTTP 200 on /login`
   - Risk: service
