#!/usr/bin/env bash
# solution/solve.sh (generated) — Oracle: renders the manifest-derived reports.
set -euo pipefail
OUT="${OUTPUT_PATH:-/app}"
mkdir -p "$OUT"
cat > "$OUT/progress.md" <<'RK_ORACLE_EOF'
# Progress

Investigation timeline for `wordpress-defacement`:

1. Reviewed alerts in `/sas` and enumerated the read-only image at `/disk`.
2. Reconstructed the attack chain: step 1 T1190 — WordPress plugin RCE (CVE-2022-1609); step 2 T1505.003 — PHP webshell planted (after step 1); step 3 T1491.001 — site defacement (after step 2); step 4 T1053.003 — cron persistence (after step 2); step 5 T1505.003 — .htaccess redirect (after step 2).
3. Swept beyond the alerts for silent artifacts (persistence, tool residue, backdoors).
4. Authored the four reports and the prioritised remediation plan.
RK_ORACLE_EOF
cat > "$OUT/intrusion-report.md" <<'RK_ORACLE_EOF'
# Intrusion Report

## Entry Point
WordPress plugin RCE (CVE-2022-1609) (T1190); PHP webshell planted (T1505.003); site defacement (T1491.001). Evidence and reconstruction below; the attack chain is given at the end.

## Intrusion Entities
| Entity | Evidence | ATT&CK |
|---|---|---|
| defaced-page (hacked, defaced) | `/var/www/html/index.html` | T1491.001 |

## Persistence Mechanisms
| Mechanism | Evidence | ATT&CK | Alerted |
|---|---|---|---|
| cron (wget, php) | `/var/spool/cron/crontabs/www-data` | T1053.003 | **no** |
| htaccess-redirect (RewriteRule, redirect) | `/var/www/html/.htaccess` | T1505.003 | **no** |

## Impact
Host confidentiality, integrity, and availability should be considered compromised until the
remediation plan is executed and verified.

## Attack Chain
T1190 → T1505.003 → {T1491.001, T1053.003, T1505.003}

- T1190 → T1505.003
- T1505.003 → T1491.001
- T1505.003 → T1053.003
- T1505.003 → T1505.003
RK_ORACLE_EOF
cat > "$OUT/vuln-report.md" <<'RK_ORACLE_EOF'
# Vulnerability Report

A CVE-driven entry vector was identified:

- CVE-2022-1609 — `/var/www/html/wp-content/plugins/contact/inc.php` (php-webshell (eval, base64_decode))

Confidence: high. Evidence cited inline.
RK_ORACLE_EOF
cat > "$OUT/baseline-report.md" <<'RK_ORACLE_EOF'
# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| wordpress-baseline (DB_PASSWORD, weak) | `/var/www/html/wp-config.php` | BAS-01 |
RK_ORACLE_EOF
cat > "$OUT/remediation-plan.md" <<'RK_ORACLE_EOF'
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
RK_ORACLE_EOF
