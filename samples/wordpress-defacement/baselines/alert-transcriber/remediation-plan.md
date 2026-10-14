# Remediation Plan

## P1 — Eradicate
1. quarantine the PHP webshell in the contact plugin — target: `/var/www/html/wp-content/plugins/contact/inc.php`.
   - Verify: `! test -f /var/www/html/wp-content/plugins/contact/inc.php`
   - Risk: service
2. restore the legitimate index page from backup — target: `/var/www/html/index.html`.
   - Verify: `index page no longer contains defacement markers`
   - Risk: service
