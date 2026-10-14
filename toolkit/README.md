# DFIR Task Toolkit — generate new tasks & reproduce results

This is the **self-contained generation kit** for the *post-compromise host forensics &
remediation-planning* (DFIR) evaluation. Everything needed to (a) **recreate a new task**, (b)
**reproduce the shipped tasks and results**, and (c) understand **how a task is built and scored**
lives in this folder.

One authored **blueprint** (a range's input dimensions) compiles into a complete
[Harbor](https://github.com/laude-institute/terminal-bench)-format task: `task.toml`,
`environment/` (Dockerfile + forensic disk + security-product feed), `instruction.md`,
`manifest.json`, the verifier, a `solution/`, and three baselines. The verifier is **not** written
per range — it is one manifest-parametrized package; only the generated `manifest.json` (plus
`discovery.py` / `verification.py` / `attribution.toml`) differs between ranges. This is the R5
generalization guarantee made operational.

> **Where things are.** The generated tasks live in [`../samples/`](../samples); the evaluation job
> records live in [`../logs/`](../logs); the failure analysis is
> [`../report.md`](../report.md). Design rationale for every
> decision below is in [`design-docs/`](design-docs) (docs 00–04). To author a brand-new range
> step by step, see [`AUTHORING.md`](AUTHORING.md).

---

## Contents of this toolkit

| Path | What it is |
|---|---|
| `generate_task.py` | Blueprint → full Harbor task package (task.toml, Dockerfile, instruction, verifier bindings, solution, baselines). |
| `build_disk.py` | Synthesises the rich, heterogeneous, **defanged** forensic disk (`/disk`) + analyst materials (`/sas`) the container mounts. |
| `selftest.py` | The **deterministic gate** — runs the real verifier runtime on the baselines and asserts oracle ≥ 0.90, no-op ≤ 0.10. |
| `run_agent.py` | Optional — runs a live Gemini policy in a network-isolated sandbox and scores it with an Opus judge. |
| `blueprints/` | The 10 authored blueprints (one per shipped range). The single hand-written input. |
| `dfir_taskgen/` | The generator package + `templates/` (instruction + the fixed verifier). |
| `rewardkit/` | The vendored reward runtime (`__init__` criterion API, `runner`, `judge`). Copied into every task's `tests/`. **Must stay a sibling of `dfir_taskgen/`** — `emit.py` resolves it as `parent.parent/"rewardkit"`. |
| `reference/` | Public-data cache `build_disk.py` reads: `attack_names.json` (ATT&CK id→name), `cve/*.json` (NVD entries), and `_extract.py` to refresh them. |
| `AUTHORING.md` | End-to-end guide for authoring a new range. |
| `task-implementation.toml` | The `harbor check` rubric used to quality-check tasks. |
| `design-docs/` | Docs 00–04: subdomain selection, verifier/GRPO reward design, scalability, and the ssh-miner reference build. |
| `.env.example` | Template for the API keys the optional model steps need. Copy to `.env`. |

---

## 0. Prerequisites

| Requirement | Version / notes |
|---|---|
| Python | 3.9+ (stdlib only for JSON blueprints; `pyyaml` only if you author YAML blueprints) |
| Docker | Docker Desktop running — needed for `harbor run`/`harbor check` and `run_agent.py`. **Not** needed for generation, `build_disk.py`, or `selftest.py`. |
| Harbor | `0.21.0` (task schema `1.4`) — `harbor --version` |
| API keys | `GEMINI_API_KEY` (agent policy) and/or `ANTHROPIC_API_KEY` (judge). **Optional** — every deterministic step runs without them. |

Generation, disk build, and the deterministic gate are **pure-Python, offline, keyless**. You only
need Docker + keys to run a live agent or the Tier-3 judge.

### API keys (only for the optional model steps)

```bash
cp .env.example .env      # then paste your real keys into .env
set -a; source .env; set +a
```

**Family separation:** use a **Gemini** judge to score a Claude policy, and an **Anthropic** judge
to score a Gemini policy — never the same family as judge and policy.

---

## 1. Reproduce everything (quickstart)

Run from this `toolkit/` directory. This regenerates all 10 tasks into `../samples/`, builds their
forensic disks, and runs the deterministic gate on each:

```bash
for bp in blueprints/*.json; do python3 generate_task.py "$bp" --out ../samples/; done && \
python3 build_disk.py ../samples/*/ && \
for t in ../samples/*/; do python3 selftest.py "$t" || echo "GATE FAILED: $t"; done
```

Expected: **10/10 tasks pass** the deterministic gate (oracle `reward=1.0`, no-op `reward=0.0`).
The shipped `../samples/` are exactly this output — regeneration is idempotent. To reproduce into a
scratch dir instead of overwriting the shipped copies, use `--out /tmp/tasks/` and diff.

---

## 2. Author a NEW range (the whole point)

You write **one file** — a blueprint. Everything else is generated.

```bash
# 1. print a skeleton blueprint to fill in
python3 generate_task.py --scaffold my-range --os ubuntu --difficulty 3 > blueprints/my-range.json
#    ... edit blueprints/my-range.json: chain, artifacts, remediation, decoys ...

# 2. generate the task package
python3 generate_task.py blueprints/my-range.json --out ../samples/

# 3. build the forensic disk + /sas feed
python3 build_disk.py ../samples/my-range

# 4. deterministic gate — MUST pass before scoring any model
python3 selftest.py ../samples/my-range
```

Full authoring rules (blueprint fields, capability taxonomy, QA gates, worked examples) are in
[`AUTHORING.md`](AUTHORING.md). Two shipped blueprints are the reference examples:
`blueprints/ssh-miner.json` (the doc-04 reference range) and `blueprints/log4shell-webshell.json`
(a structurally different CVE-entry range with decoys, timestomping, and a multi-branch chain that
exercises the same generator and verifier unchanged).

### The blueprint fields

| field | required | meaning |
|---|:--:|---|
| `range_id` | ✓ | task name / output directory |
| `platform` | ✓ | `{os, version}` |
| `difficulty` | ✓ | 1–4 (L1–L4) |
| `chain` | ✓ | ATT&CK-annotated steps: `{step, attck, desc, depends_on?}` |
| `artifacts` | ✓ | ground-truth artifacts: `{chk, path, kind, capability, alerted, weight?, match?, attck?, cve?}` |
| `remediation` | | `{chk, action, verify?, phase, risk_class?}` — phases from `precedence` |
| `precedence` | | default `[contain, eradicate, harden, rotate, verify]` |
| `no_cve_entry` | | default: true unless a `VUL-*` artifact exists |
| `alert_coverage` | | default: measured from the artifacts' `alerted` flags |
| `decoys` | | `{path, looks_malicious, benign}` benign lookalikes (yield FP checkpoints) |
| `scenario`, `description`, `tags`, `timeouts`, `judge` | | packaging/prompt metadata (defaulted) |

`capability` must start with one of `ENT / PER / BAS / VUL / Q`. `match` terms both **discriminate
checkpoints that share a path** (e.g. miner *process* vs *binary*) and name the salient in-file
evidence a real report would cite; discovery requires the cited **path** plus (when present) a
`match` term, so generic substrings can't inflate silent-recall.

> **Defanging is deliberate.** Disks are generated on ordinary workstations with AV/EDR. Attack
> content is *described, not reproduced* — no runnable payloads, IOCs are bracketed (`hxxp://`,
> `evil[.]com`, `stratum+tcp[:]//`), "binary" drops are clearly-labelled INERT samples. Every
> manifest `match` needle is a benign word, so defanging leaves grounding/discovery/scoring
> unchanged (manifest ↔ disk stays 100%).

---

## 3. Validate — the deterministic gate

`selftest.py` calls **`rewardkit.runner.run`** — the exact function `tests/test.sh` invokes — on
each baseline with the Tier-3 judge off, so only the deterministic tiers score. A green self-test
**is** a green real run of the deterministic tiers.

```bash
python3 selftest.py ../samples/docker-api-miner              # deterministic tiers only
python3 selftest.py ../samples/docker-api-miner --with-judge # also runs Tier-3 (needs keys)
```

Gate: **no-op ≤ 0.10, oracle ≥ 0.90**, and the alert-transcriber baseline's `silent_recall = 0`.

---

## 4. Score a live policy (optional)

### `run_agent.py` — no Harbor needed

Runs a Gemini agent inside a network-isolated, read-only Docker sandbox (`/disk`+`/sas` mounted
`ro`, `--network none`), then scores its five reports with an Opus judge:

```bash
set -a; source .env; set +a
python3 run_agent.py ../samples/ssh-miner                 # Gemini policy, Opus judge (default)
python3 run_agent.py ../samples/ssh-miner --judge none    # Tier 1+2 only (no judge tokens)
python3 run_agent.py ../samples/ssh-miner --local         # no Docker; host subprocess (read-only)
```

### Harbor — `harbor run` (execute an agent or the oracle)

`harbor run` takes a **job config** (a bare task path is not accepted positionally). The `oracle`
agent stages `solution/solve.sh`, so it's the fastest end-to-end check that the verifier scores
correctly:

```bash
printf '{"job_name":"oracle-docker","tasks":[{"path":"../samples/docker-api-miner"}]}\n' > /tmp/job.json
harbor run -c /tmp/job.json -a oracle -y
```

Run the oracle over all 10 as one job:

```bash
printf '{"job_name":"oracle-all","tasks":[%s]}\n' \
  "$(for t in ../samples/*/; do printf '{"path":"../samples/%s"},' "$(basename "$t")"; done | sed 's/,$//')" \
  > /tmp/oracle-all.json && harbor run -c /tmp/oracle-all.json -a oracle -y -n 4
```

### Harbor — `harbor check` (quality-check tasks against the rubric)

```bash
set -a; source .env; set +a
harbor check ../samples/ -r task-implementation.toml -a terminus-2 \
  -m gemini/gemini-3.6-flash --ae GEMINI_API_KEY=$GEMINI_API_KEY -n 3 --job-name check-all
```

> **Do not background 10 separate `harbor check`/`harbor run` processes.** `--job-name` defaults to
> a timestamp and `--jobs-dir` to `jobs/`, so simultaneous processes collide on one job directory
> and clobber each other → every trial fails with `verifier/reward.txt not found`. Use a single
> invocation and keep `-n` modest (2–4). See [Troubleshooting](#7-troubleshooting).

---

## 5. What gets generated (task package layout)

```
tasks/<range_id>/
├── task.toml                       # schema 1.4: name (dfir-eval/<id>), tags, difficulty, timeouts
├── instruction.md                  # DFIR-generic prompt, rendered with paths + scenario
├── environment/                    # Docker BUILD CONTEXT (harbor convention)
│   ├── Dockerfile                  # /disk (ro, sha256-verified), /sas (ro), /app (rw)
│   ├── disk.tar.gz(+.sha256)       # forensic image from build_disk.py (or --disk)
│   └── sas-mock/                   # security-product feed + cti/ + handoff/ analyst materials
├── tests/                          # the FIXED generic verifier + this range's bindings
│   ├── criteria.py                 # shared: citation regex, /disk|/sas resolver, helpers
│   ├── reward.toml, test.sh, manifest.json
│   ├── rewardkit/                  # VENDORED runtime (registry, runner, judge)
│   ├── structure/ grounding/ detection/ planning/ quality/
│   ├── detection/discovery.py      # GENERATED: one rk.discovered() per artifact
│   ├── detection/attribution.toml  # GENERATED: judge prompt templated on the chain
│   ├── planning/verification.py    # GENERATED: one rk.step_verified() per remediation
│   ├── planning/quality.toml       # Tier-3 plan-quality judge (fixed)
│   └── quality/q_items.toml        # Tier-3 Q-dimension judge (fixed, eval-only)
├── solution/solve.sh               # renders the oracle deliverables (used by `harbor run -a oracle`)
├── assets/disk/                    # extracted disk TREE for inspection (not the build context)
└── baselines/
    ├── oracle/                     # 5 reports from the manifest — rubric ceiling
    ├── noop/                       # evidence-free but plausible — the hostile case
    └── alert-transcriber/          # alerts only — isolates P1 (silent_recall = 0)
```

Only `manifest.json`, `discovery.py`, `verification.py`, and `attribution.toml` carry
range-specific values; everything else under `tests/` (including the vendored `rewardkit/`) is
copied verbatim for every range. **Do not edit a task's vendored `tests/` per range** — change the
generator template under `dfir_taskgen/templates/tests/` and regenerate.

### The Harbor reward-file contract

`tests/test.sh` runs the vendored runtime, then publishes results to `/logs/verifier/`:

- **`/logs/verifier/reward.txt`** — the single float in `[0,1]` Harbor uses as the score. This is
  the threshold gate: `structure == 1` **and** `detection ≥ 0.70` **and** `plan ≥ 0.70`.
- **`/logs/verifier/reward-full.json`** — the human diagnostic (per-axis scores + `outcome`).

> ⚠️ **`reward.json` in `/logs/verifier/` is RESERVED by Harbor.** If a file literally named
> `reward.json` exists there, Harbor prefers it over `reward.txt` and parses it as
> `dict[str, float | int]` — so **every value must be numeric**. The diagnostic dump carries
> non-numeric fields (`"outcome": "scored"`, `"quality": null` when the judge is off), so it is
> published as **`reward-full.json`**, never `reward.json`.

---

## 6. The 10 shipped ranges

Difficulty L1–L4, mixed Linux/Windows, CVE-entry and no-CVE. `run` = verdict of the canonical
Gemini-3.6-Flash policy run in [`../logs/run-all/`](../logs/run-all) (the run the failure report
analyses).

| range_id | platform | L | chain | artifacts | CVE-entry | run |
|---|---|:--:|:--:|:--:|:--:|:--:|
| docker-api-miner | Ubuntu 22.04 | 3 | 6 | 5 | no | PASS |
| jenkins-groovy | Ubuntu 22.04 | 3 | 7 | 6 | yes (CVE-2024-23897) | PASS |
| log4shell-webshell | Ubuntu 22.04 | 3 | 6 | 6 | yes (CVE-2021-44228) | **FAIL** |
| postgres-copyprogram | CentOS Stream 9 | 4 | 6 | 6 | no | PASS |
| rdp-ransomware | Windows Server 2022 | 3 | 8 | 6 | no | PASS |
| redis-unauth | Debian 12 | 2 | 5 | 5 | no (CVE-2022-1609 ctx) | **FAIL** |
| smb-eternalblue | Windows 10 | 4 | 7 | 7 | yes (CVE-2017-0144) | **FAIL** |
| ssh-miner | CentOS 7 | 2 | 8 | 9 | no | **FAIL** |
| struts-exfil | RHEL 9 | 4 | 8 | 6 | yes (CVE-2023-50164) | PASS |
| wordpress-defacement | Ubuntu 20.04 | 2 | 5 | 5 | yes | **FAIL** |

Every range is fully regenerable from `blueprints/<id>.json`. The five failures are the useful
yield of the experiment — see [`../report.md`](../report.md) §5.

---

## 7. Troubleshooting

- **`verifier/reward.txt not found` (`RewardFileNotFoundError`) under parallel `harbor check`/`run`,
  fine serially.** Infrastructure contention, not a task bug. Fixes: use a **single**
  `harbor check ../samples/ -n 3` invocation (never 10 backgrounded processes → shared job dir);
  lower `-n`; raise Docker Desktop CPU/memory; clear orphaned containers:
  ```bash
  docker ps -a --filter "name=__env-main" --format '{{.ID}}' | xargs -r docker rm -f
  ```
- **`sha256 -c` fails at Docker build.** The `environment/disk.tar.gz` is stale/missing — rerun
  `python3 build_disk.py ../samples/<id>`.
- **`harbor run` fails at the verifier with an empty `/logs/verifier`** in a restricted sandbox
  (bind-mount limitation). Verify the task directly:
  ```bash
  docker build -t t -f ../samples/<id>/environment/Dockerfile ../samples/<id>/environment
  docker run --rm t bash -c 'mkdir -p /logs/verifier /app; bash /solution/solve.sh; bash /tests/test.sh; cat /logs/verifier/reward.txt'
  ```
- **Judge shows `skipped`.** Expected without `REWARDKIT_JUDGE` + the matching API key; the
  deterministic tiers still score fully.
- **Refreshing the public-data cache.** `reference/attack_names.json` and `reference/cve/` are a
  license-clean cache. Re-run `python3 reference/_extract.py` only when refreshing sources.
