# Post-Compromise DFIR Agent Eval — Final Report (Failure Cases)

**Subject under test:** Gemini 3.6 Flash · terminus-2 scaffold · 10 generated post-compromise DFIR ranges
**Verifier:** manifest-parametrized hybrid verifier (deterministic Tier 1+2; judge off), 70%-per-axis pass bar
**Run:** `jobs/run-all` (fixed verifier) · reward = 1 iff detection ≥ 0.70 **and** plan ≥ 0.70 **and** structure complete

---

## Summary

We built **10 tasks** across the post-compromise host-forensics subdomain (cryptomining, ransomware,
web-shell, unauth-service, and lateral-movement scenarios on Linux and Windows images). Gemini 3.6 Flash
**passed 5 and failed 5** (pass@1 = 0.50, mean reward 0.50).

The five passes — **docker-api-miner, jenkins-groovy, postgres-copyprogram, rdp-ransomware, struts-exfil** —
cleared both axes (detection 0.81–0.96, plan 0.73–1.00) and are not discussed further here.

Validity controls held throughout: the oracle baseline scores 1.0 and the no-op baseline 0.0 on all 10 ranges,
so the failures below reflect model behaviour, not scoring artifacts. Every failure was traced to the agent's
own trajectory; **all five are genuine capability failures** (reasoning / grounding / output-mechanics /
decomposition), not task-design defects, cheating, or missing instructions.

| Failure | Detection | Plan | Blocking axis | Failure mode |
|---|---|---|---|---|
| wordpress-defacement | 0.00 | 0.00 | structure (incomplete) | **Output-format collapse** — invalid JSON, nothing written |
| redis-unauth | 0.00·gated | 0.90 | detection (fabrication) | **Fabricated persistence artifact** |
| log4shell-webshell | 0.00·gated | 0.83 | detection (fabrication) | **Mis-cited pseudo-path** (`/dev/tcp`) |
| ssh-miner | 0.89 | 0.38 | plan | **Thin, unverified remediation plan** (variance) |
| smb-eternalblue | 0.86 | 0.55 | plan | **Under-verified plan + one missed artifact** |

`gated` = detection was strong pre-gate but forced to 0 by a fabricated citation (zero-tolerance fabrication gate).

---

## Failure case 1 — wordpress-defacement · output-format collapse

**Scores:** detection 0.00, plan 0.00, structure 0.00 → `incomplete_output`. Every axis zero; 0/5 artifacts.

**What happened.** This is not a forensics failure — it is an output-mechanics failure. The agent generated
its five markdown deliverables by emitting large multi-line report bodies inside the terminus-2 JSON tool-call
response. That content broke the response format, and the scaffold rejected the turns:

> `Previous response had warnings: - Extra text detected after JSON object`
> `Previous response had parsing errors: ERROR: Invalid JSON: Invalid control character at: line 18 column 1021`

Because the tool calls were embedded in malformed JSON, **the write commands never executed** — `ls -la /app`
returns an empty directory turn after turn. The agent nonetheless believed it had succeeded:

> step 8: *"All files in `/app` and `/sas` are already written and verified. I will execute `ls -la /app` to finish."* → `/app` is empty.

It then spent the remaining turns re-emitting the same oversized JSON and hitting the same parse error,
burning **141,953 completion tokens — roughly 10× a normal run — across only 11 steps** before the episode
ended with nothing on disk.

**Root cause & classification.** **Genuine — instruction/output-format following under a strict JSON tool
interface**, compounded by overconfident false-belief of completion. The model's forensic *content* was never
the problem; it could not deliver a large structured artifact through the response channel without corrupting
it. There is a scaffold-interaction component (a more tolerant parser or a file-write tool would have salvaged
the run), which is worth noting for the harness but does not change that the model produced invalid output.

---

## Failure case 2 — redis-unauth · fabricated persistence artifact

**Scores:** plan 0.90 (strong), silent-recall 1.0, discovered 5/5 — but detection **hard-gated to 0** by
fabrication.

**What happened.** The agent investigated well and its remediation plan was among the best in the run. It then
asserted a persistence artifact that does not exist in the evidence:

> intrusion-report.md: cites `` `/lib/.hide.so` `` as an LD_PRELOAD / rootkit library.

`/lib/` exists on the image but `/lib/.hide.so` does not — the model inferred a hidden rootkit `.so` (a
plausible Redis-compromise TTP) and cited it as if it had found it. Under the mandatory-citation rule ("every
finding must be grounded in evidence"), that is a fabrication, and a non-zero fabrication rate zeroes the
detection axis.

**Root cause & classification.** **Genuine — P2 evidence-grounding failure.** Asserting an inferred-but-absent
artifact is exactly the behaviour the fabrication gate exists to catch; the model let a strong prior about how
Redis boxes get rootkitted override what was actually on disk.

---

## Failure case 3 — log4shell-webshell · mis-cited pseudo-path

**Scores:** plan 0.83 (strong), discovered 5/6, chain 0.55 — detection **hard-gated to 0** by one fabricated
citation of 54.

**What happened.** The agent correctly reconstructed a reverse shell but backtick-cited a non-file path:

> intrusion-report.md: *"The attacker spawned a reverse shell process invoking `bash -i` over `/dev/tcp`
> targeting C2 IP `198.51.100.136`."* — cited as `` `/dev/tcp` ``.

`/dev/tcp/<host>/<port>` is a bash networking pseudo-device, not a file on disk, so the citation does not
resolve and is scored as fabrication. The forensic reasoning is correct; the *evidence citation* is not.

**Root cause & classification.** **Genuine but borderline — a grounding-discipline slip.** The model cited a
conceptual mechanism as if it were a filesystem artifact. It also exposes the fabrication gate's bluntness: a
single mis-cite out of 54 erases an otherwise-strong detection axis. In eval-reporting mode (graded
fabrication penalty) this range is a near-pass; under the training-faithful hard-zero it fails.

---

## Failure case 4 — ssh-miner · thin, unverified remediation plan (consistency failure)

**Scores:** detection 0.89 (discovered 8/9), structure clean — but plan **0.38** (`step_verified` 3/11).

**What happened.** The agent found nearly everything and wrote a well-structured plan that *covers* every
finding (coverage 1.0) and reconciles the change ticket correctly (including rejecting the planted BlueKeep
CVE). But the individual remediation steps omit a verification action for **five artifact fixes** — the miner
process, the systemd unit, the sudoers backdoor, the sshd config, and the MySQL binding are removed/hardened
with **no "confirm it worked" check**:

> *"3. Process Termination: Kill active process `/tmp/.X11-unix/.xorg`. 4. Binary Quarantine: Move
> `/tmp/.X11-unix/.xorg` to `/var/quarantine/.xorg.bak`."* — action stated, no verification step.

**Root cause & classification.** **Genuine — P4 closure failure**, and a pointed **consistency** finding: the
*same range* produced a fully-verified plan (plan 0.91) on the immediately preceding run. Gemini 3.6 Flash
knows how to write verification steps; it does not do so **reliably**. Run-to-run plan variance this large is
itself a reportable weakness — it means a single-seed score is not trustworthy for this model.

---

## Failure case 5 — smb-eternalblue · under-verified plan + one missed artifact

**Scores:** detection 0.86 (discovered 6/7, chain 0.54) — passes — but plan **0.55** (`step_verified` 4/9).

**What happened.** On the Windows EternalBlue image the agent detected six of seven artifacts and mapped the
chain, but its plan under-verifies: one artifact remediation (CHK-03) and several containment/verification
steps lack a confirmable check. Detection clears the bar; the plan does not.

**Root cause & classification.** **Genuine — P1/P4 near-miss.** A missed persistence artifact plus a plan that
prescribes fixes without verifying them. No fabrication, structure clean — a straightforward "close but
incomplete" result, the most common shape of frontier failure on this benchmark.

---

## Cross-cutting observations

1. **Two distinct grounding failures (redis, log4shell)** cost otherwise-passing ranges their entire detection
   axis over 1–2 citations. The model's forensic recall is strong; its **citation discipline** is the weak
   point — inventing an artifact (redis) or citing a non-file concept (log4shell). This is P2, the axis we
   made deterministic precisely to catch it.
2. **Two plan failures (ssh-miner, smb)** are P4 closure gaps — the model remediates but does not **verify**
   the fix. This mirrors the published SecRespond finding that models "correctly kill the process and delete
   the file, then fail to … confirm the service still runs."
3. **One output-mechanics collapse (wordpress)** is orthogonal to forensics: the model could not emit a large
   structured artifact through the JSON interface without corrupting it, and falsely believed it had.
4. **Consistency is a first-class weakness.** ssh-miner swung plan 0.91 → 0.38 and wordpress swung detection
   0.92 → 0.00 across consecutive runs. Any headroom number for this model needs ≥3 seeds per range.

**Bottom line:** all five failures are the failure *kinds* the instrument is designed to surface — evidence
fabrication, unverified remediation, and output-format breakdown — with no task-design artifact among them.
