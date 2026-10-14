# Authoring a Post-Compromise DFIR Task — Blueprint → Harbor

This guide takes a new author from an idea to a Harbor-runnable task. You author **one file**
(a blueprint); everything else — the task package, the forensic disk, the verifier — is
generated. Execution is entirely through `harbor run` / `harbor check`.

```
blueprint.json  --generate_task.py-->  task package  --build_disk.py-->  disk.tar.gz
                                             |
                                             +--> harbor run -a oracle | nop | <model>
```

The blueprint defines the **range** (the compromised host and its ground truth). It does
**not** define the agent or the judge — those are runtime choices you pass to `harbor run`.

---

## 1. What gets generated (Harbor-canonical layout)

`python3 generate_task.py blueprints/ssh-miner.json --out tasks/` produces:

| Path | What it is |
|---|---|
| `instruction.md` | The DFIR prompt the agent sees (analysis machine, read-only `/disk`, cite evidence, produce 5 reports). |
| `task.toml` | Task metadata + `[verifier.env]` (`ANTHROPIC_API_KEY`, `REWARDKIT_JUDGE`). |
| `environment/Dockerfile` | Builds the environment: extracts `disk.tar.gz` to `/disk` (read-only), mounts `/sas`, `WORKDIR /app`. |
| `tests/test.sh` | The verifier Harbor runs after the agent. Prints `reward=`, writes `reward.txt`, exits `0` iff reward is 1. |
| `solution/solve.sh` | The **Oracle** solver — writes the manifest-derived perfect reports. `harbor run -a oracle` runs this. |
| `assets/disk.tar.gz`, `assets/sas-mock/` | The forensic image + the security-product feed (built by `build_disk.py`). |
| `tests/manifest.json` | The **ground truth** (from the blueprint). The one per-range input the fixed verifier reads. |
| `tests/rewardkit/`, `tests/{structure,grounding,detection,planning,quality}/` | The vendored, generic verifier — identical for every DFIR task. |

Only `manifest.json` and a few generated bindings change per range; the verifier code is fixed.

---

## 2. Crafting the blueprint

Start from a skeleton:

```
python3 generate_task.py --scaffold my-range --os ubuntu --difficulty 3 > blueprints/my-range.json
```

Then fill it in. Fields:

| Field | Req | Meaning |
|---|:--:|---|
| `range_id` | yes | task name / output dir |
| `platform` | yes | `{os, version}` (e.g. `{"os":"ubuntu","version":"22.04"}`; `os:"windows"` for Windows ranges) |
| `difficulty` | yes | 1–4 (L1 easy … L4 hard) |
| `chain` | yes | ATT&CK-annotated attack steps: `{step, attck, desc, depends_on?}` |
| `artifacts` | yes | ground-truth artifacts: `{chk, path, kind, capability, alerted, weight?, match?, attck?, cve?}` |
| `remediation` |  | `{chk, action, verify, phase, risk_class?}`; `phase` from `precedence` |
| `precedence` |  | default `[contain, eradicate, harden, rotate, verify]` |
| `no_cve_entry` |  | default: true unless a `VUL-*` artifact exists |
| `alert_coverage` |  | default: measured from the artifacts' `alerted` flags |
| `decoys` |  | `{path, looks_malicious, benign}` — benign lookalikes (yield false-positive checkpoints) |
| `scenario`, `description`, `tags`, `judge` |  | prompt/packaging metadata (defaulted) |

**`capability`** must start with one of `ENT` (intrusion entity), `PER` (persistence),
`BAS` (baseline weakness), `VUL` (CVE entry), `Q` (investigation quality) — the five
SecRespond dimensions. The suffix (e.g. `PER-V01`, `PER-S01`) is free-form.

**`match`** terms serve two jobs: they *discriminate two checkpoints that share a path*
(e.g. miner process vs. binary), and they name the salient in-file evidence a real report
would cite. Discovery requires the cited **path** plus (when present) a `match` term.

### Rules that keep the task measuring something (the QA gates)

A well-formed blueprint makes the no-op score ≤ 0.10 and the oracle ≥ 0.90. To hold that:

1. **At least one silent artifact** (`"alerted": false`) with a path **not shared** with any
   alerted artifact. Silent artifacts are the P1 signal — a model that only transcribes the
   alerts scores `silent_artifact_recall = 0`.
2. **A branching chain.** Give steps a `depends_on` so there's a hub (entry → exec → {impact,
   persistence×N, anti-forensics}); the oracle renders it and the verifier reconstructs it.
3. **Remediation with a `verify`** predicate per entry, phases drawn from `precedence`.
   Detection-only forensic evidence (e.g. a cleared-log residue) gets **no** remediation entry
   — it's a finding you don't remediate, and coverage excludes it.
4. **CVE entry?** set `no_cve_entry: false` and give a `VUL-*` artifact with a `cve`. Otherwise
   `no_cve_entry: true` and the vuln-report checkpoint requires the "no CVE" conclusion.

`generate_task.py` validates the blueprint and refuses malformed ones. Run `selftest.py`
(below) to confirm the gates before you go near Harbor.

---

## 3. Adapting / enhancing from the SecRespond dataset

SecRespond ships a `checklist.md` per range (authoritative, Chinese; `checklist.en.md` is the
translation). Use it as a **structural template** for your blueprint — the taxonomy, the chain
shapes, and the difficulty model transfer directly. Author your **own** synthetic range from
the *method* and public technique knowledge (MITRE ATT&CK, CVE/NVD, CIS); do not copy
SecRespond's disk or checklist text. SecRespond stays held-out eval, never training input.

### Map a `checklist.md` CHK to a blueprint artifact

A real checklist entry looks like:

```
### CHK-08: masquerade service WindowsHealthSvc detected  `PER-V03`
- Evidence: HKLM\...\Services\WindowsHealthSvc, binPath C:\ProgramData\WindowsHealth\WindowsHealthSvc.ps1
- Detection score: found service / cite registry / attribute to post-exploit persistence
- Plan score: stop+delete the service; also delete payload dir; check adjacent services
```

That becomes one artifact (+ its remediation):

```json
{ "chk": "CHK-08", "path": "/ProgramData/WindowsHealth/WindowsHealthSvc.ps1",
  "kind": "masquerade-service", "capability": "PER-V03", "alerted": false,
  "weight": 2.0, "attck": "T1543.003", "match": ["WindowsHealthSvc", "ProgramData"] }
```

The mapping, field by field:

| checklist.md | blueprint |
|---|---|
| `### CHK-NN: <title>` | one `artifacts[]` entry (`chk`) — or a `chain` step for a pure narrative step |
| the capability tag (`PER-V03`, `ENT-N01`, `BAS-03`, `Q-02`, `VUL-*`) | `capability` |
| **Evidence** path | `path` (+ a `match` term for the salient string) |
| in `sas-mock/alerts.json`? | `alerted: true` if surfaced by the feed, else `false` (silent) |
| **Detection score** (found+evidence+attribution) | scored by the verifier's discovery + grounding + Tier-3 attribution |
| **Plan score** (correctness+completeness) | a `remediation[]` entry with `action` + `verify` |
| "Plan score: N/A" (detection-only) | omit the remediation entry |
| the CHK narrative order | `chain` steps with `attck` + `depends_on` |

Weight the **silent** and high-value checkpoints up (`2.0`); leave routine baseline checks at
`1.0`.

### Difficulty knobs (from SecRespond's difficulty model)

Tune these in the blueprint to move up the L1→L4 curve:

- **Alert coverage** (primary): more silent artifacts / fewer alerted ones → harder.
- **Correlation hops**: longer `depends_on` chains to the entry point.
- **Persistence classes**: 2 (easy) → 5–6 with ≥1 disguised (hard).
- **Anti-forensics**: none → log clear → + timestomp → + selective wipe/decoys.

### Enhancements beyond a straight port (doc 01 §6)

- **Decoys** → add benign lookalikes; they create false-positive checkpoints the original
  corpus lacks and test precision.
- **Silent/alerted flips** → flip a finding's `alerted` to isolate transcription vs. investigation.
- **Cross-runtime** → add a persistence step in a second service/runtime (the hardest axis).
- **Multimodal / in-place editing** → the doc-01 Δ extensions, once the base range is clean.

---

## 4. Generate the task and build the disk

These two authoring-time steps are the only Python you run; execution is Harbor.

```
python3 generate_task.py blueprints/my-range.json --out tasks/
python3 build_disk.py tasks/my-range
```

`build_disk.py` is the instance layer done synthetically, and it produces a **rich,
multi-format** forensic image (closes R6 / doc 01 §6): each manifest artifact is materialised
at its real path in a format-appropriate file (syslog / web log / CSV / JSON / config /
crontab / systemd unit / registry hive / `.evtx` / inert binary sample / source / markup),
woven into hundreds of lines of benign noise, with a rotated+gzipped log, a truncated
"cleared-window" log, and a partially-overwritten file. It also writes the Δ1/Δ2 analyst
materials into `assets/sas-mock/`: `cti/` (a vendor advisory as text + PDF + page-image PNGs +
a timeline chart, using **real MITRE ATT&CK names and NVD CVE data** baked license-clean under
`reference/`) and `handoff/` (a pre-filled change-ticket with stale entries to reconcile, a
findings JSON schema, an intake PDF). It prints `manifest<->disk 100%` — the QA gate — and
every scoring needle stays recoverable with `grep`/`strings`/`zcat`/`jq`/`pdftotext` (added to
`environment/Dockerfile`).

All synthetic attack content is **defanged** (`hxxp://`, `evil[.]com`, `stratum+tcp[:]//`;
tools described, not reproduced; binaries written as inert labelled samples, never real
PE/ELF) so it does not trip antivirus/EDR on ordinary workstations. Needles are benign words,
so defanging changes nothing the verifier scores. For the CTI modality-swap probe (doc 01 §5
probe E), add `--cti-image-only` to omit the OCR/text layer from the page images:

```
python3 build_disk.py tasks/my-range --cti-image-only
```

To refresh the baked ATT&CK/CVE reference data from the internet, re-run
`python3 reference/_extract.py <dir-with-downloads>` (see its header for the two source URLs).

Sanity-check the verifier **before Harbor** (no API needed):

```
python3 selftest.py tasks/my-range
```

Expect `ALL DETERMINISTIC GATES PASS` (oracle ≥ 0.90, no-op ≤ 0.10, alert-transcriber
`silent_recall = 0`). If it fails, fix the blueprint, not the verifier.

---

## 5. Run in Harbor

The fastest way to get oriented is to run the task in three configurations — Oracle, Nop, and
the model under test — then read the trajectory.

First, set the **judge** for the verifier (Anthropic Opus), so the LLM-graded checkpoints
score. Keep the judge family different from the policy family — here a **Gemini policy scored
by an Opus judge**:

```
export ANTHROPIC_API_KEY=...           # the judge
export REWARDKIT_JUDGE=anthropic/claude-opus-5
```

**1. Skim the four key files** in the generated task: `instruction.md`, `task.toml`,
`environment/Dockerfile`, `tests/test.sh` (plus the optional `solution/solve.sh`).

**2. Oracle** — runs `solution/solve.sh` against the environment; a sanity-check that the task
is solvable.

```
harbor run -p tasks/my-range -a oracle
```

Expected reward: **1**. If not, the solution or verifier is broken.

**3. Nop** — does nothing; spins up the environment and exits. Proves the verifier doesn't pass
on inaction.

```
harbor run -p tasks/my-range -a nop
```

Expected reward: **0**. If you see 1, the verifier is satisfied by the default state and the
task isn't measuring anything.

**4. Model under test** — the configuration you capture into `logs/` for submission:

```
harbor run -p tasks/my-range -a terminus-2 -m gemini/gemini-3.6-flash
```

**5. IMPORTANT — inspect the trajectory.** Read `jobs/<job>/<trial>/agent/trajectory.json` and
`verifier/reward.txt` to see the real model behavior (what it explored, which silent artifacts
it missed, where the plan fell short).

### Quality-check each task with `harbor check`

Before submitting, run each task through `harbor check` to catch authoring problems
(under-specified instructions, gameable verifiers, anti-cheat holes). Use the TB3
task-implementation rubric — it codifies what a "good task" means:

```
harbor check tasks/my-range -r
```

Rubric: https://github.com/harbor-framework/terminal-bench-3/blob/main/rubrics/task-implementation.toml

---

## 6. Reading the reward

`reward.json` (in the workspace) reports per-axis scores; `verifier/reward.txt` is the binary
pass/fail Harbor keys on:

- `detection` and `plan` — the two axes, **never summed**; the diagnostic value is the gap.
- `reward` — 1 only if **both** axes ≥ 0.70 (the pass threshold), else 0.
- `silent_artifact_recall` — the headline P1 metric: recall over the silent artifacts. Low ⇒
  reactive tunnel vision (the model followed the alerts and stopped).
- `grounding` / `fabrication_rate` — did findings cite resolvable evidence, or invent it.
- `quality` — the Tier-3 Q-dimension (honesty/calibration/impact); eval-only by default.

A strong DFIR agent typically shows **detection > plan** — it finds the compromise (even
silent parts) but its remediation is incomplete or unverified. That gap is exactly what these
tasks exist to measure.

---

## Appendix — gate checklist for a new blueprint

- [ ] ≥ 1 silent artifact (`alerted:false`), unique path
- [ ] each artifact has a distinct `path`, or a `match` needle if it shares one
- [ ] `chain` has `depends_on` forming a hub (branching), ATT&CK ids on every step
- [ ] every `remediation` entry has a `verify`; phases ⊆ `precedence`
- [ ] `no_cve_entry:false` ⇒ a `VUL-*` artifact with a `cve`
- [ ] `selftest.py` prints ALL DETERMINISTIC GATES PASS
- [ ] `harbor run -a oracle` ⇒ reward 1; `-a nop` ⇒ reward 0
