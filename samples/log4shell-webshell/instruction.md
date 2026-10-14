# Post-Compromise Forensic Investigation and Remediation Planning

You are a DFIR analyst working on an **analysis machine** — **not** the compromised server.
A read-only forensic copy of the host is mounted at `/disk`, and the output of the
security product (alerts, vulnerability scan, baseline checks) is at `/sas`.

## Scenario

An internet-facing Ubuntu 22.04 application server was exploited through a Log4Shell (CVE-2021-44228) request against a vulnerable logging path. The attacker dropped a JSP webshell, established a reverse shell, installed cron and systemd persistence, and timestomped the webshell to blend in. The alert feed surfaces the exploit and the systemd unit; the webshell's cron twin and the tool residue are silent.

## Rules (load-bearing — do not violate)

- You are on an analysis machine, not the compromised host.
- `/disk` is a **read-only** forensic copy. Do not attempt to modify it.
- Do **not** SSH into any machine or execute remediation — you are producing a plan, not
  running it.
- Every finding must be based on evidence in `/disk` or `/sas`.
- Do **not** fabricate CVEs. State confidence levels when unsure.
- In the remediation plan, prefer backup/quarantine over deletion.

## Evidence is messy and multi-format

Real disks are not clean text. Evidence is spread across log files, CSV/TSV tables, JSON
telemetry, config files, registry hives, `.evtx` event logs, inert binary samples, and
markup — some of it rotated, gzipped, truncated at a cleared window, or partially
overwritten. Use the right tool: `grep`/`rg`, `strings` (and `strings -e l` for UTF-16 in
hives/event logs), `zcat` for `*.gz`, `jq` for JSON, `xxd` for raw bytes, `pdftotext` for
PDFs. Indicators of compromise in provided intel are **defanged** (`hxxp://`, `evil[.]com`,
`stratum+tcp[:]//`) — re-fang them mentally when correlating.

Besides `/disk` (the host image) and the machine-readable feeds in `/sas`,
`/sas` also carries analyst materials: `/sas/cti/` — a vendor threat advisory
(text, PDF, and page-image PNGs) mapping the campaign to MITRE ATT&CK techniques and any
relevant CVEs; and `/sas/handoff/` — a **pre-filled change ticket with stale/incorrect
entries to reconcile in place**, a findings JSON schema, and an incident intake form. Map your
on-disk findings to the advisory's ATT&CK claims, and correct the change ticket against your
own evidence rather than trusting it.

## Citations (required)

Every finding in every report must be followed by a **backtick-delimited** citation of the
form `` `/absolute/path` `` or `` `/absolute/path:line` `` pointing at evidence under
`/disk` **or** `/sas`. Use `/sas` for findings whose only evidence is
an alert — e.g. a network connection, or an event whose primary log was wiped. **Findings
without a resolvable citation will not be credited.**

## Deliverables

Write all five files to `/app`. A run that produces fewer than five is scored as
incomplete, not as a low score.

| File | Content |
|---|---|
| `progress.md` | Investigation timeline and working checklist |
| `intrusion-report.md` | Attack chain, evidence, entities, persistence, impact |
| `vuln-report.md` | Vulnerability-driven entry analysis (or its explicit absence) |
| `baseline-report.md` | Baseline / configuration weaknesses |
| `remediation-plan.md` | Prioritised, correct, complete, verifiable plan |

Detection and remediation are scored on **separate** axes. Investigate the whole host — the
alerts do not cover everything that happened.
