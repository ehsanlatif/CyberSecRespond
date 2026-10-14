# Evaluation job records (logs)

These are the raw **Harbor job outputs** behind
[../report.md](../report.md). Model under test:
**Gemini 3.6 Flash** with the `terminus-2` scaffold, over the 10 ranges in [../samples/](../samples).

## What's here


| Folder      | Job(s)                                             | Role                                                                                                                            |
| ----------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `run-all/`  | policy run                                         | **Canonical run — the failure report is based on this.** 10/10 trials completed, 0 errors: **5 pass, 5 fail.**                  |
| `trail-1/`  | `run-all` + `oracle-all` + `nop-all` + `check-all` | A full earlier trail: the live policy plus the QA-gate baselines (oracle, no-op) and the rubric `harbor check`.                 |
| `trail-2/`  | `run-all` + `oracle-all` + `nop-all` + `check-all` | A second trail — the *adjacent run* the report cites for run-to-run variance (e.g. ssh-miner plan 0.38 here vs 0.91 elsewhere). |
| `analysis/` | markdown                                           | Per-run write-ups (`gemini-3.6-flash-run-analysis.md`, `...run2-analysis.md`) and the earlier `FINAL-REPORT-failure-cases.md` / `DFIR-Eval-Failure-Report.md`. |


### Canonical run (`run-all/`) — verdicts

- **PASS (5):** docker-api-miner, jenkins-groovy, postgres-copyprogram, rdp-ransomware, struts-exfil
- **FAIL (5):** log4shell-webshell, redis-unauth, smb-eternalblue, ssh-miner, wordpress-defacement

These five failures are exactly the ones dissected in the failure report §5. Job-level totals are in
`run-all/result.json` (mean reward 0.5; input/cache/output tokens; cost).

> **Note on the trails.** `run-all/` is the clean 0-error run and is the one to read first.
> The `oracle-all` (reward=1.0 everywhere) and `nop-all` (reward=0.0 everywhere) jobs are the
> load-bearing QA-gate evidence: they show the verifier ceiling and floor hold on all 10 ranges.

## Anatomy of a trial directory

Each `<range>__<id>/` trial holds:

```
<range>__<id>/
├── config.json                 # agent (terminus-2), model, task path
├── result.json                 # this trial's reward + token/cost stats
├── trial.log                   # harbor orchestration log
├── agent/
│   ├── trajectory.json         # the full agent transcript (turns, tool calls) — read this for failure modes
│   ├── recording.cast          # asciinema recording of the terminal session
│   └── terminus_2.pane         # final tmux pane capture
├── artifacts/
│   └── manifest.json           # the task's ground-truth manifest used for scoring
└── verifier/
    ├── reward.txt              # the single float Harbor scored (the gate; 1.0 iff both axes >= 0.70)
    ├── reward-full.json        # per-axis diagnostic (structure/grounding/detection/plan/…)
    └── test-stdout.txt         # verifier stdout
```

`reward-full.json` is where the report's per-axis numbers come from. Example — `run-all/ssh-miner`:

```json
{ "structure": 1.0, "grounding": 1.0, "detection": 0.8857, "plan": 0.3846,
  "quality": null, "detection_pre_gate": 0.8857, "reward": 0.0,
  "silent_artifact_recall": 1.0, "fabrication_rate": 0.0, "outcome": "scored" }
```

detection 0.89 (pass) but plan 0.38 (fail: unverified remediation) → `reward = 0.0`. That is the
P4 failure mode the report describes.

## Reproducing these jobs

See [../toolkit/README.md](../toolkit/README.md) §4 (`harbor run` / `harbor check` /
`run_agent.py`). Run-to-run variance is large; a shippable headroom number needs ≥3 seeds per range.