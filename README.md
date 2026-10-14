# CyberSecRespond — Post-Compromise DFIR Agent Evaluation

A self-contained, machine-scorable evaluation for **post-compromise host forensics &
remediation planning (DFIR)**. Hand an agent a read-only forensic image (`/disk`) and a partial
security-product alert feed (`/sas`); score whether it independently finds what *else* happened,
grounds every claim in on-disk evidence, and writes a verified remediation plan.

This repository contains everything needed to **replicate** the published results and **extend**
the benchmark with new ranges, new artifact types, new scoring criteria, or new models:

- **10 generated Harbor tasks** (Linux + Windows, L1–L4 difficulty, CVE-entry and no-CVE)
- **A blueprint → task generator** — one declarative JSON file compiles into a complete task
- **A fixed, manifest-parametrized hybrid verifier** (deterministic Tier 1+2, optional LLM judge Tier 3)
- **Raw evaluation logs** for Gemini 3.6 Flash (`terminus-2` scaffold) plus oracle/no-op QA gates
- **The failure analysis report** and the design documents behind every decision

Model under test: **Gemini 3.6 Flash** · Harness: **[Harbor](https://harborframework.com)** /
Terminal-Bench (Harbor `0.21.0`, task schema `1.4`) · Held-out reference benchmark:
**[SecRespond](https://github.com/Alibaba-NLP/qqr/tree/main/data/secrespond)**.

---

## Headline result

|                                        | Detection                          | Planning | Complete solve (both ≥ 70%) |
| -------------------------------------- | ---------------------------------- | -------- | --------------------------- |
| **Gemini 3.6 Flash — this evaluation** | 80.7 *(pre-gate)* · 64.0 *(gated)* | 71.8     | **5 of 10 tasks**           |

The five failures concentrate on the two axes the instrument was built to isolate:

- **Citation discipline (P2)** — inventing (`redis-unauth`) or mis-citing (`log4shell-webshell`)
  evidence; the fabrication gate makes a single ungrounded citation decisive.
- **Plan verification (P4)** — remediating without confirming the fix worked (`ssh-miner`, `smb-eternalblue`).
- One orthogonal **output-format collapse** (`wordpress-defacement`).

Full analysis: [report.md](report.md) §5. Visual overview: [docs/DFIR-Agent-Evaluation-overview.pdf](docs/DFIR-Agent-Evaluation-overview.pdf).

---

## Repository layout

```
CyberSecRespond/
├── README.md                  ← you are here
├── report.md                  ← headline report: capability, verifier/reward, headroom, scale plan, failure analysis
├── docs/
│   └── DFIR-Agent-Evaluation-overview.pdf
├── samples/                   ← the 10 generated Harbor tasks (each fully self-contained)
│   └── <range_id>/
│       ├── task.toml · instruction.md
│       ├── environment/       ← Dockerfile + disk.tar.gz (+sha256) + sas-mock/ feed
│       ├── tests/             ← the fixed verifier + this range's manifest.json bindings
│       ├── solution/solve.sh  ← oracle deliverables (used by `harbor run -a oracle`)
│       ├── baselines/         ← oracle / noop / alert-transcriber reports
│       └── assets/disk/       ← extracted disk tree for inspection
├── logs/                      ← raw Harbor job records (see logs/README.md)
│   ├── run-all/               ← canonical policy run (the report is based on this)
│   ├── trail-1/  trail-2/     ← full earlier trails: run-all + oracle-all + nop-all + check-all
│   └── analysis/              ← per-run write-ups and earlier failure reports
└── toolkit/                   ← everything needed to generate tasks and reproduce results
    ├── generate_task.py       ← blueprint → task package
    ├── build_disk.py          ← synthesises the defanged forensic disk + /sas analyst materials
    ├── selftest.py            ← deterministic QA gate (oracle ≥ 0.90, no-op ≤ 0.10)
    ├── run_agent.py           ← optional: live Gemini policy in a sandbox, no Harbor needed
    ├── blueprints/            ← the 10 authored blueprints (the only hand-written input)
    ├── dfir_taskgen/          ← generator package + templates/ (instruction + fixed verifier)
    ├── rewardkit/             ← vendored reward runtime (criterion API, runner, judge)
    ├── reference/             ← license-clean ATT&CK names + NVD CVE cache
    ├── design-docs/           ← docs 00–04: dataset selection, verifier/GRPO, scalability, worked example
    ├── AUTHORING.md           ← step-by-step guide to authoring a new range
    ├── task-implementation.toml  ← `harbor check` rubric
    └── .env.example           ← template for the optional API keys
```

### How it fits together

```
blueprint.json ──generate_task.py──▶ task package ──build_disk.py──▶ forensic disk (/disk + /sas)
                                          │
                                          ├─ selftest.py ......... deterministic gate (oracle ≥ 0.90, no-op ≤ 0.10)
                                          └─ harbor run / check ... live policy → logs/ → failure report
```

The verifier is **fixed for the whole subdomain** and parametrized only by each task's generated
`manifest.json` (plus `discovery.py`, `verification.py`, `attribution.toml`). That is what lets the
corpus scale from 10 to 1,000+ ranges while staying machine-scorable.

---

## Replicating the results

### 0. Prerequisites

| Requirement | Needed for | Notes |
|---|---|---|
| Python 3.9+ | everything | stdlib only for JSON blueprints; `pyyaml` only for YAML blueprints; `tomli` on Python < 3.11 for the Tier-3 judge |
| Docker Desktop | `harbor run/check`, `run_agent.py` | **not** needed for generation, disk build, or the deterministic gate |
| Harbor `0.21.0` | `harbor run/check` | `harbor --version` |
| `GEMINI_API_KEY` / `ANTHROPIC_API_KEY` | live policy, Tier-3 judge | optional — every deterministic step runs offline without keys |

```bash
git clone https://github.com/ehsanlatif/CyberSecRespond.git
cd CyberSecRespond/toolkit
```

### 1. Regenerate all tasks and run the deterministic gate (offline, keyless)

To leave the committed `samples/` untouched, regenerate into a scratch directory:

```bash
mkdir -p /tmp/regen && for bp in blueprints/*.json; do python3 generate_task.py "$bp" --out /tmp/regen/; done && python3 build_disk.py /tmp/regen/*/ && for t in /tmp/regen/*/; do python3 selftest.py "$t" || echo "GATE FAILED: $t"; done
```

**Expected:** 10/10 tasks pass (oracle `reward = 1.0`, no-op `reward = 0.0`, alert-transcriber
`silent_recall = 0`). The note `no --disk supplied` is informational, because `build_disk.py`
creates the disk in the next step.

Generation is deterministic. Compared with `samples/`, the only differences are cosmetic: the random
change-ticket number in `sas-mock/handoff/change-ticket.md`, and tarball timestamps, which change
`disk.tar.gz` and its `.sha256`. Manifests, verifiers, instructions, baselines, and disk contents
are identical.

To regenerate **in place** (overwrites `samples/`), use `--out ../samples/` instead.

### 2. Score a live policy without Harbor — `run_agent.py`

Runs a Gemini agent inside a network-isolated, read-only Docker sandbox (`--network none`,
`/disk` + `/sas` mounted `ro`), then scores its five reports:

```bash
cp .env.example .env
```

Fill in `.env`, then load it:

```bash
set -a; source .env; set +a
```

```bash
python3 run_agent.py ../samples/ssh-miner --model gemini-3.6-flash
```

Useful flags: `--judge none` (Tier 1+2 only, no judge tokens), `--local` (no Docker; read-only
host-subprocess allowlist), `--max-turns N`.

**Family separation:** score a Gemini policy with an Anthropic judge and a Claude policy with a
Gemini judge. Never use the same family as both judge and policy.

### 3. Reproduce the Harbor jobs in `logs/`

`harbor run` takes a job config. Oracle over all 10 tasks (verifier ceiling, expect 1.0 everywhere):

```bash
printf '{"job_name":"oracle-all","tasks":[%s]}\n' "$(for t in ../samples/*/; do printf '{"path":"../samples/%s"},' "$(basename "$t")"; done | sed 's/,$//')" > /tmp/oracle-all.json && harbor run -c /tmp/oracle-all.json -a oracle -y -n 4
```

Policy run. The canonical `logs/run-all/config.json` sets the agent in the job config
(`terminus-2` + `gemini/gemini-3.6-flash`). To reproduce it exactly:

```bash
printf '{"job_name":"run-all","agents":[{"name":"terminus-2","model_name":"gemini/gemini-3.6-flash"}],"tasks":[%s]}\n' "$(for t in ../samples/*/; do printf '{"path":"../samples/%s"},' "$(basename "$t")"; done | sed 's/,$//')" > /tmp/run-all.json && harbor run -c /tmp/run-all.json -y -n 3
```

`GEMINI_API_KEY` must be exported in the shell (see step 2).

Rubric quality check (`check-all` in the trails):

```bash
harbor check ../samples/ -r task-implementation.toml -a terminus-2 -m gemini/gemini-3.6-flash --ae GEMINI_API_KEY=$GEMINI_API_KEY -n 3 --job-name check-all
```

> Run **one** Harbor invocation with modest `-n` (2–4). Backgrounding several processes makes them
> share a job directory and fail with `verifier/reward.txt not found`. See
> [toolkit/README.md §7](toolkit/README.md#7-troubleshooting).

Run-to-run variance is large (e.g. `ssh-miner` plan 0.38 in one trail vs 0.91 in another). A
shippable headroom number needs **≥ 3 seeds per range**.

### 4. Read a result

Each trial writes `verifier/reward.txt` (the gated score Harbor reports) and
`verifier/reward-full.json` (per-axis diagnostic):

```json
{ "structure": 1.0, "grounding": 1.0, "detection": 0.8857, "plan": 0.3846,
  "quality": null, "detection_pre_gate": 0.8857, "reward": 0.0,
  "silent_artifact_recall": 1.0, "fabrication_rate": 0.0, "outcome": "scored" }
```

`reward = 1.0` iff `structure == 1` **and** `detection ≥ 0.70` **and** `plan ≥ 0.70`.
Detection and plan are **never summed** in any reported metric. The gap between them is the
diagnostic signal. See [logs/README.md](logs/README.md) for the anatomy of a trial directory.

---

## Extending the benchmark

### A. Author a new range (most common)

You write **one blueprint**. Everything else is generated.

```bash
python3 generate_task.py --scaffold my-range --os ubuntu --version 22.04 --difficulty 3 > blueprints/my-range.json
```

Edit `blueprints/my-range.json` (chain, artifacts, remediation, decoys), then generate, build, and gate it:

```bash
python3 generate_task.py blueprints/my-range.json --out ../samples/ && python3 build_disk.py ../samples/my-range && python3 selftest.py ../samples/my-range
```

Key blueprint fields (full reference in [toolkit/README.md §2](toolkit/README.md) and
[toolkit/AUTHORING.md](toolkit/AUTHORING.md)):

| field | meaning |
|---|---|
| `chain` | ATT&CK-annotated steps `{step, attck, desc, depends_on?}`, a DAG that scores chain topology |
| `artifacts` | ground truth `{chk, path, kind, capability, alerted, weight?, match?, attck?, cve?}`. Set `alerted: false` for the **silent** artifacts the agent must find on its own |
| `remediation` | `{chk, action, verify?, phase}`, with phases ordered by `precedence` (`contain → eradicate → harden → rotate → verify`) |
| `decoys` | benign look-alikes that produce false-positive checkpoints |

Rules that keep a range measuring something:

- `capability` must start with `ENT`, `PER`, `BAS`, `VUL`, or `Q`.
- `match` needles must be **benign words** that appear in the defanged evidence. They tell apart
  checkpoints that share a path (e.g. miner *process* vs *binary*).
- Keep a meaningful share of artifacts `alerted: false`. The alert-transcriber baseline must score
  `silent_recall = 0`.
- **Never score a model on a range that fails `selftest.py`.**

Reference examples: `blueprints/ssh-miner.json` (the doc-04 worked example) and
`blueprints/log4shell-webshell.json` (CVE entry, decoys, timestomping, multi-branch chain).

### B. Port a range from SecRespond

[AUTHORING.md §3](toolkit/AUTHORING.md) maps a SecRespond `checklist.md` checkpoint (CHK) onto a
blueprint artifact and explains its difficulty knobs. **Keep SecRespond held out:** use it as an
evaluation reference and never as training data. It is licensed CC-BY-NC-SA-4.0 and is
intentionally not redistributed here.

### C. Add a new artifact `kind`

Evidence text for each artifact kind lives in the `KIND_EV` table in
[toolkit/build_disk.py](toolkit/build_disk.py). An unknown kind still builds, using a generic
evidence line plus your `match` needles. For realistic disks, add an entry:

1. Add `"my-kind": ["defanged, descriptive evidence line containing your match words"]` to `KIND_EV`.
   Use `%IP%`, `%C2%`, `%POOL%` placeholders and bracketed IOCs (`hxxp://`, `evil[.]com`).
2. If the kind is a dropped binary, add it to `BINARY_KINDS` so it is written as an INERT labelled sample.
3. Rebuild with `build_disk.py` and re-run `selftest.py`.

> **Defanging is mandatory.** Attack content is *described, not reproduced*: no runnable payloads
> or exploit command lines. This keeps the repo safe on machines with AV/EDR and leaves scoring
> unchanged, because every `match` needle is a benign word.

### D. Add or change a verifier criterion

The verifier is shared by every range. **Edit the template, not a task's vendored `tests/`:**

1. Add a module under `toolkit/dfir_taskgen/templates/tests/<tier>/` (`structure`, `grounding`,
   `detection`, `planning`, `quality`) using the `rewardkit` criterion API:

   ```python
   import rewardkit as rk
   from rewardkit import criterion

   @criterion(description="what this checks, in one line", weight=1.0)
   def my_check(workspace) -> bool:   # or return a float in [0, 1]
       findings = rk.shared._findings(workspace)
       ...
   ```

2. For range-specific checks, emit them from the manifest in `toolkit/dfir_taskgen/emit.py`
   (as `discovery.py` / `verification.py` are), so the verifier code stays fixed.
3. LLM-judged criteria go in a TOML (`[[criterion]]` entries), like `planning/quality.toml`.
4. Regenerate **all** tasks and re-run the gate on every one. A criterion change is a subdomain-wide change.

### E. Evaluate a different model or scaffold

- **Harbor:** swap `-a <agent> -m <provider/model>` in the `harbor run` command above.
- **`run_agent.py`:** pass `--model <gemini-model>`. To add another provider, replace the
  `gemini()` call and `TOOLS` schema in [toolkit/run_agent.py](toolkit/run_agent.py) with a small
  adapter. The sandbox and scoring stay the same.
- **Judge:** set `REWARDKIT_JUDGE=anthropic/<model>` or `gemini/<model>` with the matching key.
  If unset, Tier 3 reports `skipped` and the deterministic tiers still score fully.

### F. Scale the corpus

[toolkit/design-docs/03-task-scalability-and-regeneration.md](toolkit/design-docs/03-task-scalability-and-regeneration.md)
describes the sampling grid (attack signature × platform × difficulty), the QA gates, and the
curriculum for going from 10 to ~3,000 ranges / ~15,000 prompts. Report **signature count and
range count separately**. They are not the same number.
[design-docs/02](toolkit/design-docs/02-verifier-design-and-grpo-reward.md) explains how the same
verifier doubles as a GRPO reward function.

### Non-negotiables when extending

1. No-op ≤ 0.10 and oracle ≥ 0.90 before any model is scored.
2. Detection and plan are never summed in a reported metric.
3. Refusals are a separate outcome bucket, not reward 0.
4. Signature count ≠ range count.
5. SecRespond never enters the training loop.

---

## Troubleshooting

See [toolkit/README.md §7](toolkit/README.md#7-troubleshooting). The most common problems:

- **`sha256 -c` fails at Docker build:** `disk.tar.gz` is stale. Re-run `build_disk.py`.
- **`reward.txt not found` under parallel Harbor runs:** use one invocation with lower `-n`.
- **Judge shows `skipped`:** expected without `REWARDKIT_JUDGE` and a matching key.

## Data & safety notes

- All forensic disks are **synthetic and defanged**. "Binaries" are clearly labelled inert text
  samples, and IOCs use documentation IP ranges and bracketed domains.
- `reference/` contains MITRE ATT&CK® names (© The MITRE Corporation, CC BY 4.0) and NVD CVE
  entries (U.S. Government public domain).
- `logs/*/result.json` records the absolute paths from the machine the jobs originally ran on.
  That is provenance metadata only and isn't needed for replication.
- API keys are read from the environment only. Never commit a populated `.env`. It is git-ignored.
