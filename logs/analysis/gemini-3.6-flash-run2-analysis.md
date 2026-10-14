# Gemini 3.6 Flash — Run 2 Analysis (fixed verifier) + recalculated job report

**Run:** `implementation/jobs/run-all` · job `2b3b5270-…` · started 2026-08-16 09:06 · gemini-3.6-flash / terminus-2
**Verifier at run time:** the FM-01…FM-07 fixes from run 1 (structure/entry, step-block, tokens, chain, CVE, match-case, fabrication allowlist).
**This analysis adds one more fix (FM-02b)** found during the trajectory review; see §3.
**Method:** deliverables reconstructed from each trajectory and re-scored offline; per-criterion detail recovered.
Reconstruction reproduces the recorded axis scores **exactly on 10/10** trials — faithful and deterministic.

---

## 0. Recalculated overall job report

`result.json` is **stale** — 4 trials hit a `RuntimeError` at agent-setup on first attempt (the known
recording-tools/apt flake, not a verifier fault), were retried under new IDs, and the aggregate was never
rewritten. It also captured a transient docker pass (`__zpbPHu2`) that a later re-run replaced. The table
below is recomputed from the **actual current per-trial verifier outputs** on disk.

| Range | det | plan | struct | fab | silent | reward |
|---|---|---|---|---|---|---|
| docker-api-miner | 0.833 | 0.600 | 1.0 | 0.000 | 1.00 | 0 |
| jenkins-groovy | 0.949 | 0.636 | 1.0 | 0.000 | 1.00 | 0 |
| log4shell-webshell | 0.000·gated | 0.583 | 1.0 | 0.011 | 1.00 | 0 |
| postgres-copyprogram | 0.959 | 0.619 | 1.0 | 0.000 | 1.00 | 0 |
| rdp-ransomware | 0.813 | 0.636 | 1.0 | 0.000 | 1.00 | 0 |
| redis-unauth | 0.000·gated | 0.691 | 1.0 | 0.053 | 1.00 | 0 |
| smb-eternalblue | 0.670 | 0.455 | 1.0 | 0.000 | 0.67 | 0 |
| ssh-miner | 0.783 | 0.679 | 1.0 | 0.000 | 1.00 | 0 |
| struts-exfil | 0.710 | 0.455 | 1.0 | 0.000 | 0.50 | 0 |
| wordpress-defacement | 0.183 | 0.275 | 1.0 | 0.000 | 0.00 | 0 |

**As-run (the verifier that actually executed): pass@1 = 0/10, mean reward = 0.000.**
- mean detection (post-gate) 0.590 · mean detection **pre-gate 0.765** · mean plan 0.563
- detection ≥0.70 on **6/10**; plan ≥0.70 on **0/10** → plan is the universal blocker
- structure passes on **10/10** (run-1 FM-01 worked); fabrication false-positives gone except two GENUINE
  cases (log4shell, redis)
- outcome buckets: 10 `scored`, 0 remaining `harness_error` (the 4 RuntimeErrors were retried successfully)

The run-1 verifier artifacts are **gone**. But the plan axis sits suspiciously just under 0.70 on almost
every range — which the trajectory review explains.

---

## 1. Why plan clustered at ~0.60–0.69 — one residual verifier defect (FM-02b)

The plan shortfall is entirely `step_verified` (coverage = 1.0 and ordering ≈ 1.0 everywhere). Breaking the
`step_verified` failures down by checkpoint type:

- **Artifact CHKs** (a real `/path`): mostly pass; a few genuine misses (docker CHK-04, smb CHK-03/04, …).
- **Remediation-only CHKs** (contain / rotate / verify — no artifact, matched by the manifest ACTION
  string): **fail on essentially every range** — CHK-20 (contain), CHK-07 (rotate), CHK-21/22 (verify).

The cause is the same class of bug as run 1: `step_verified` for a remediation-only CHK needled on the
manifest's action phrase ("block attacker source IP inbound"), which no agent reproduces verbatim. **The
agents did the work.** ssh-miner, verbatim:

```
#### Step 1.1: Network Containment (Block Attacker IP)
- Action: Add iptables drop rule for attacker IP `198.51.100.78`.
- Verification: iptables -L -n -v | grep 198.51.100.78
#### Step 3.1: Account Credential Rotation & Session Invalidation
- Action: Reset passwords for `root` and `devops`, kill active sessions.
- Verification: passwd -S root and passwd -S devops
```

Containment and rotation are present **and verified** — the verifier just couldn't locate them.

**FM-02b (implemented):** for remediation-only CHKs, derive locator needles from the salient content words
of the action phrase (drop stopwords) and require ≥2 to co-occur, instead of an exact action-string match.
Artifact CHKs are unchanged. `dfir_taskgen/templates/tests/criteria.py` (`_needles` / `_step_block_for`),
propagated to all 10 tasks.

### 1.1 Validity gate still holds (over-credit guard)
- **oracle = 1.0 on 10/10.**
- **noop = 0.0 on 10/10**, noop **plan stays at floor 0.058–0.075** — FM-02b credits real steps, not empty
  reports.
- Manual read confirms passing agents earned it (jenkins: real `iptables … DROP` + `ss` verification; its
  one remaining `step_verified` fail is CHK-07, a **genuine** missing credential-rotation step).

---

## 2. True result after FM-02b (same agent outputs, corrected verifier)

Re-scoring the **same** reconstructed reports with FM-02b (agent behaviour unchanged; only the verifier):

| Range | det | plan (was) | verdict | genuine assessment |
|---|---|---|---|---|
| docker-api-miner | 0.83 | **0.80** (0.60) | **PASS** | competent; was verifier-suppressed |
| jenkins-groovy | 0.95 | **0.91** (0.64) | **PASS** | competent; only misses CHK-07 (rotate) |
| postgres-copyprogram | 0.96 | **0.80** (0.62) | **PASS** | competent |
| rdp-ransomware | 0.81 | **0.82** (0.64) | **PASS** | competent |
| ssh-miner | 0.78 | **0.91** (0.68) | **PASS** | competent |
| log4shell-webshell | 0.0·gated | 0.75 | FAIL | **genuine** — 1 malformed cite (fabrication) |
| redis-unauth | 0.0·gated | 0.89 | FAIL | **genuine** — 4 fabricated rootkit libs |
| smb-eternalblue | 0.67 | 0.55 | FAIL | **genuine** near-miss (5/7 artifacts, thin plan) |
| struts-exfil | 0.71 | 0.64 | FAIL | **genuine** plan near-miss (unverified steps) |
| wordpress-defacement | 0.18 | 0.28 | FAIL | **genuine** collapse (1/5 artifacts) |

**pass@1 = 5/10 (gate mode), mean reward ≈ 0.50; mean plan 0.735.** In `RK_FAB_MODE=graded` redis (plan 0.89)
and log4shell (plan 0.75) can also clear once their genuine fabrication is a graded penalty rather than a hard
zero — so eval-mode pass@1 is ~5–7/10.

> **Honesty note.** This 5/10 is *higher* than the 25–40% band doc 01 §4.6 predicts for frontier models at the
> 70%-per-axis bar. Two non-exclusive reasons: (a) our **generated** ranges may be easier than SecRespond's
> hand-authored ones; (b) a single reconstructed run has no seed variance. The oracle=1.0 / noop=floor gate
> argues against FM-02b being simply lenient, but **multi-seed re-runs + a judge-swap are needed to trust the
> rate.** Treat 5/10 as "this run's agent outputs, corrected verifier," not a calibrated headroom number.

---

## 3. The five genuine failures (trajectory-grounded)

### GF-1 · wordpress-defacement — shallow recognition + overconfidence  **(the canonical P1 failure)**
- Detection 0.18: **discovered 1 of 5 artifacts**, silent-recall 0.0, chain 0.375. Ran a normal number of
  probes (18 `/disk`-touching commands) but closed after **22 steps** (vs ssh-miner's 47) having recognised
  and reported only one malicious artifact.
- Verbatim (final step 22): *"All 5 required files … created in `/app` with full details, accurate backtick
  citations … mapping to MITRE ATT&CK techniques, CVE analysis, baseline checks, and change ticket
  reconciliation."* — high confidence, 1/5 coverage.
- Classification: **genuine** — reactive/shallow investigation + overconfident closure, exactly the failure
  the benchmark exists to measure. Note the **variance**: the same range scored det 0.92 in run 1.

### GF-2 · redis-unauth — fabricated persistence artifacts  **(genuine grounding failure)**
- 4 fabricated citations, all inventions the agent inferred but never located on disk: `/lib/.hide.so` (×3)
  and `/lib/modules/.../exp.so` — a rootkit `.so` and an LD_PRELOAD library. Parent dirs exist but the files
  do not. Detection hard-gated to 0 despite plan 0.89.
- Classification: **genuine** P2 failure — asserting artifacts that aren't in evidence (the exact behaviour
  the fabrication gate exists to punish).

### GF-3 · log4shell-webshell — one malformed citation  **(genuine but minor; harshly gated)**
- Single fabricated cite: `` `/disk/cron.d/apache-cache:7` `` — the agent dropped `/etc` from the cron path
  (`/disk/etc/cron.d/…`), so the parent doesn't resolve. 1 of 93 citations (1.1%) → detection → 0, plan 0.75.
- Classification: **genuine** grounding slip, but the hard-zero for a single path typo is the FM-07 severity
  tension; in graded mode this range is a near-pass.

### GF-4 · smb-eternalblue — incomplete detection + thin plan  **(genuine near-miss)**
- Discovered **5 of 7** artifacts (det 0.67, just under 0.70), chain 0.54; plan 0.55 (several artifact steps
  lack a verification action). No fabrication, structure clean.
- Classification: **genuine** — the model missed two persistence artifacts and under-verified its plan.

### GF-5 · struts-exfil — plan near-miss  **(genuine)**
- Detection 0.71 (passes). Plan 0.64: coverage 1.0, ordering 1.0, but a few artifact-step verifications
  missing. One silent artifact (CHK-03 `/root/.ssh/authorized_keys`) named in prose but not credited — its
  `match=['ssh-ed25519','attacker']` needs the key-type string the agent didn't paste (borderline residual).
- Classification: **mostly genuine** plan gap; a small residual on the silent-recall discriminator.

### No cheating, no missing-instruction failures observed. Infra: 4 first-attempt RuntimeErrors (agent-setup flake), all retried clean.

---

## 4. The report questions (run-2 data)

### 4.1 Capability targeted
Post-compromise DFIR (doc 01 §3), four separable probes. Run-2 evidence per probe:

| Probe | Capability | Run-2 result |
|---|---|---|
| **P1** Scope expansion (*what else to look for?*) | silent-recall | **1.0 on 8/10**; genuinely fails on wordpress (1/5) and smb (5/7) |
| **P2** Evidence grounding (*can I cite it?*) | grounding + fabrication | strong (grounding ≥0.99) except 2 genuine fabricators (redis, log4shell) |
| **P3** Attribution (*where in the chain?*) | chain topology | partial (chain 0.37–0.54 where it fails); correct node sets, weaker edges |
| **P4** Closure (*fixed AND verified?*) | plan axis | **now measurable** post-FM-02b: 7/10 plan ≥0.70 |

### 4.2 How SOTA was probed
- Gemini 3.6 Flash × terminus-2, 1 seed × 10 generated ranges.
- Controls (doc 01 §5.4): oracle (1.0/10) and noop (0.0/10) re-verified after every verifier change — the
  gate that keeps the fixes honest.
- Still unrun and recommended next: scaffold axis (Claude Code / Codex / OpenCode parity), seed variance
  (≥3/cell), the five diagnostic probes A–E, and a judge-swap on the Tier-3 items.

### 4.3 Landscape (external, doc 01 §4)
- **Knowledge ≠ capability** — CAIBench (2510.24317): 70–89% on security *knowledge* → 20–40% multi-step.
- **Subdomain unsolved** — SecRespond (2607.26791): **0/23** frontier models complete detection+remediation on
  any range; best Opus 4.7 **79.0 detect / 65.7 plan**; persistence detection 58.8% ≪ entity 75.4%; planning
  floor (investigation quality) **31.8%**; agentless scanner finds **2.1%** of persistence.
- **Documented failure = reactive tunnel vision** ("respond to given clues instead of actively
  investigating"). Run 2 reproduces it **once** (wordpress GF-1) — but 8/10 ranges show the opposite
  (silent-recall 1.0), i.e. Flash usually *does* investigate proactively, with high run-to-run variance.
- **Elicitable** — a procedural skill lifted GPT-5.4 26%→83% on ssh-miner; brittle on broad ranges.
- Calibration: TB3 targets ≤30% solve; 70%-per-axis ≈ 25–40% frontier band. Our 5/10 sits above it (§2 note).

### 4.4 Failure modes found (this run)
| Tag | Mode | Class | Ranges |
|---|---|---|---|
| GF-1 | Shallow recognition + overconfident closure | genuine (P1) | wordpress |
| GF-2 | Fabricated persistence artifacts | genuine (P2) | redis |
| GF-3 | Malformed citation (path typo) → fab-gate | genuine (P2), harshly gated | log4shell |
| GF-4 | Incomplete detection + thin plan | genuine (P1/P4) | smb |
| GF-5 | Plan under-verification | genuine (P4) | struts |
| — | Remediation-only step matching | **verifier residual → FIXED (FM-02b)** | all (was) |
| — | Agent-setup RuntimeError | infra flake (retried clean) | 4 first attempts |

Per doc 01 §2.1 R3, the surviving failures are the wanted kind (reasoning/grounding/decomposition), not task
artifacts. After FM-02b there is **no remaining reward-blocking verifier artifact** in this run.

---

## 5. Bottom line & next steps
1. **As-run, the job is pass@1 = 0/10** — but 5 of those zeros were the FM-02b verifier residual, not the
   model. **Corrected, the same outputs are 5/10** with 5 genuine failures (2 fabrication, 2 near-miss, 1
   collapse).
2. **Deploy FM-02b and re-run** for authoritative numbers; add ≥3 seeds/range (run-to-run variance is large —
   wordpress swung 0.92→0.18 detection across runs) and a judge-swap before quoting any pass rate.
3. Consider making `RK_FAB_MODE=graded` the eval default so a single path typo (log4shell) doesn't erase a
   strong detection axis; keep hard-zero for the training loop (doc 02 G4).
4. Small residual: silent-recall discriminators that require a literal token (`ssh-ed25519`) — match on any
   one discriminator OR the key-type family (struts GF-5).

*Supersedes the numeric results in `gemini-3.6-flash-run-analysis.md` (run 1), which remains the record of the
FM-01…FM-07 fixes.*
