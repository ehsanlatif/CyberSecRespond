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
