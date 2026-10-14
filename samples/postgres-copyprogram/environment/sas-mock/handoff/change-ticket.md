# CHANGE TICKET  CHG-6386  (DRAFT — reconcile against your findings)

> A previous shift pre-filled this remediation ticket from the SAS alerts ALONE. It is known
> to be incomplete and contains stale/incorrect lines. Correct it IN PLACE against your own
> investigation of /disk; cite evidence for every change. Do not author from scratch.

| # | Action | Target | Status | Note |
|---|--------|--------|--------|------|
| 1 | Block source IP inbound | 203.0.113.9 | proposed | STALE: prior shift used the wrong IP; confirm the real origin from /disk |
| 2 | Patch CVE-2019-0708 (BlueKeep) | RDP | proposed | WRONG: not the entry vector for this host — verify against /sas/cti |
| 3 | Remove cron miner | /var/spool/cron/root | DONE | UNVERIFIED: marked done with no evidence — re-check |
| 4 | (add) silent persistence you discover | /etc/pgdaemon.conf | TODO | ticket omits everything not alerted — add the rest |

## Reviewer checklist
- [ ] Every action maps to a cited artifact under /disk or /sas
- [ ] Fix the wrong IP (row 1) and wrong CVE (row 2)
- [ ] Downgrade row 3 from DONE to VERIFIED-or-OPEN with evidence
- [ ] Add the silent (non-alerted) artifacts the prior shift missed
