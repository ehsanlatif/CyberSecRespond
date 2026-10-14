# Remediation Plan

## P0 — Contain
1. block the attacker IP inbound and take the site into maintenance.
   - Verify: `attacker IP is blocked at the web edge`
   - Risk: network

## P1 — Eradicate
2. quarantine the PHP webshell in the contact plugin — target: `/var/www/html/wp-content/plugins/contact/inc.php`.
   - Verify: `! test -f /var/www/html/wp-content/plugins/contact/inc.php`
   - Risk: service
3. restore the legitimate index page from backup — target: `/var/www/html/index.html`.
   - Verify: `index page no longer contains defacement markers`
   - Risk: service
4. remove the www-data cron entry — target: `/var/spool/cron/crontabs/www-data`.
   - Verify: `! test -f /var/spool/cron/crontabs/www-data`
   - Risk: runtime
5. remove the malicious .htaccess redirect — target: `/var/www/html/.htaccess`.
   - Verify: `! grep -q RewriteRule /var/www/html/.htaccess`
   - Risk: service

## P2 — Harden
6. update the vulnerable plugin past the CVE-2022-1609 fix.
   - Verify: `plugin version is patched`
   - Risk: service

## P3 — Rotate
7. rotate the WordPress DB and admin credentials.
   - Verify: `credential rotation timestamps are recent`
   - Risk: auth

## P4 — Verify
8. restart the web stack and confirm the site serves the real homepage.
   - Verify: `systemctl is-active apache2 and HTTP 200 on /`
   - Risk: service
