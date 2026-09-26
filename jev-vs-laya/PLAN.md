# PLAN: Jev vs Laya, same-payload comparison for security-finding triage

*Draft v2, updated in review round 1 (Lavish: `.lavish/jev-vs-laya-design.html`). Branch:
`experiment/jev-vs-laya`, cut from `experiment/typesafe-jev` at cf88ca2. Harness is
imported from `../jev-triage-experiment/` unchanged; everything new lives here.*

## 1. Premise

The Jev evaluation (concluded 2026-09-23, branch `experiment/typesafe-jev`) measured
TypeSafe's closed System One model as a first-pass triage filter over 1,793 findings
from seven universes. Laya (convaiinnovations/laya, Apache 2.0) is an open-weights
System 1 decision engine: same typed-question paradigm (`choice`, `score`, `noul`),
same calibrated-probability response shape, 421M and 322M parameter checkpoints,
single forward pass. Laya even speaks Jev's wire protocol (`POST /v1/systemone`).
Laya's own benchmark admits its Jev numbers are third-party and never same-payload.
This study closes that gap: **byte-identical states and questions, the same gate,
the same gold sets, three identical arms, one stochastic model and one deterministic
model.**

What is new here relative to the Jev paper:

1. The first same-payload head-to-head between a closed and an open System One model.
2. A calibration suite (Brier, ECE, NLL, AUROC against operator labels) that the
   Jev paper never measured.
3. A determinism contrast: Jev samples (3-repetition voting) versus Laya's single
   deterministic forward pass, measured as an experiment; N-rep voting is not a
   deployment recommendation.
4. Consumer-hardware economics: full system telemetry (CPU, RAM, GPU, VRAM) during
   every local run, from which hardware requirements are extrapolated.
5. A Jev-labeled RLCD fine-tuning exercise that tests whether Laya responds to a
   cybersec fine-tune at all, before anyone invests in hand-crafted datasets.

## 2. Arms (review round 1: three identical arms)

| Arm | Model | Context | Reps | Purpose |
|---|---|---|---|---|
| A | Jev jev-1.13.0 (hosted API), batch size 1 | large (134 KB bodies accepted) | 3 | closed-vendor reference at the parity config |
| B | convaiinnovations/laya-typed-decisions (421M) | 1024 tokens | 2 (determinism check) | open-weights arm; trained incl. a synthetic security-incidents workflow |
| C | convaiinnovations/laya-multilingual (322M), max_len 8192 | 8192 tokens | 2 (determinism check) | open-weights arm with no truncation |

Protocol decisions from review round 1:

- **Identical arm set, repetition scheme per model class.** Same protocol everywhere:
  single finding per request (batching findings is impossible under Laya's context
  limits, and Jev runs batch-1 for parity), step-1 gate at 0.5. Jev runs three
  repetitions with majority voting; Laya runs two repetitions that serve only as a
  bit-identity determinism check, because a deterministic single forward pass
  produces the same answer every time by design.
- **English root dropped.** The 512-token checkpoint is not usable for this task and
  adds no measurement the B-versus-A comparison lacks; removed entirely.
- **Repetitions: 3 for Jev, 2 for Laya.** The measured dispersion of the Jev study
  (SD 0.001 to 0.013, unanimous-status 96.7 to 100 percent outside fragmt's
  closure-label noise) means a 3-rep majority is operationally as stable as 5; the
  only loss is near-gate granularity (k-of-3 instead of k-of-5), and near-gate
  findings route to the agent under any threshold in the 0.30 to 0.60 band, so the
  operational effect is nil. For Laya the two repetitions are bit-identical by
  construction, which the determinism check verifies and the paper reports.
  N-rep voting stays an experiment measurement, not a daily-activity recommendation.
- **Typed-decisions is the starved end.** With the English root gone, arm B's
  1024-token context is the tightest budget in the study; the truncation policy of
  Section 3 governs it.

## 3. Protocol (parity decisions)

1. **Byte-identical payloads.** The state builder (`harness.state_mv`, fresh-init
   semantics) and the two-step cascade (`is_confirmed` noul gate at 0.5,
   `state_sufficient` ride-along, step-2 closure choice between *dismissed* and
   *not-security*) run unchanged. Laya receives the exact same JSON state and
   question objects. States are rebuilt once from the existing details caches and
   frozen to disk before any arm runs.
2. **Same universes, same labels.** All seven universes (cavet 663, fragmt 40,
   corpus-1 zero control, corpus-2 337, corpus-3 475, corpus-4 8, corpus-5 270)
   with the gold sets of the Jev study, unchanged.
3. **Laya deviations handled, documented.** Choice cap 100 (our closure has 2
   options), state cap 50,000 characters (ours peak at 8.1 KB), `usage.output_tokens`
   always 0, extra response fields ignored, unknown `model` ids silently rerouted
   (we pass explicit checkpoint ids and verify the echo per response).
4. **Truncation policy (frozen in P0).** Per checkpoint: state budget = max_len
   minus the question head; truncation order is `cavet_lookup` first, then
   `source_excerpt` tail, never the finding core; identical policy in every Laya
   arm; truncation incidence reported per universe. Preflight estimate on cavet
   (chars/4): median 394, p95 591, max 2,031 tokens; over 1024: 0.2 percent;
   over 8192: none.

## 4. Calibration (agreed in review round 1)

For every arm, score P(confirmed) = the step-1 probability against operator labels.

- **Metrics.** Brier score, ECE (10 equal-width bins), NLL, AUROC; reliability
  curves per arm; per-universe breakdowns. Also the step-2 closure distribution
  where relevant, secondary.
- **Label sets.** Primary: the 138 operator verdicts (cavet 98, fragmt 40), which
  carry full confirm/non-confirm labels. Secondary: the benchmark corpora gold
  piles (confirmed versus rest), reported with the unlabeled-rest caveat from the
  Jev paper.
- **Temperature fitting.** Jev is served as-is (its temperature is the vendor's).
  For Laya, temperature is fitted on the **cavet label set (dev split)** and frozen
  before any evaluation on fragmt or the corpora (eval splits). Both raw and fitted
  Laya numbers are reported. No post-hoc refit after seeing eval results.

## 5. Concurrency, batch-size spike, and telemetry

- **Request concurrency.** Findings are independent; concurrent workers drive the
  per-finding requests (Laya arms through the library directly, not
  `laya-serve`, which is single-worker and 503s above 16 concurrent).
- **Batch-size spike (both Laya variants).** Batched forward passes
  (`predict_batch`) should be numerically identical to sequential passes, but GPU
  kernels do not guarantee it. Spike: batch sizes 1, 8, 16, 32 on arms B and C over
  a fixed slice, comparing every answer against ground truth at each size, to
  determine whether GPU load or batch width measurably changes accuracy before the
  production sweeps pick a batch size.
- **Full logging.** As in the Jev experiment, every request and response pair is
  recorded, plus per-call timings. New for local arms: a 1 Hz telemetry stream
  per run (CPU, RAM, GPU utilization, VRAM, via Windows performance counters in a
  side process) so hardware requirements can be extrapolated from measured load.

## 6. Runtime (validated 2026-09-26)

- Hardware: local AMD Radeon RX 9060 XT 16 GB (RDNA 4, gfx1200), Windows 11.
- Primary path: native Windows venv with AMD's ROCm preview PyTorch wheels
  (torch 2.13 from the gfx120X index, Adrenalin 26.8.1); CPU venv alongside as the
  zero-risk fallback (full sweep roughly a day, pin interop threads to 1).
  WSL2 ROCm is the production-grade alternative; ONNX DirectML is plan C;
  torch-directml is not viable. Laya's TileLang fast path is CUDA-only and unused.
- All resident checkpoints: about 2.3 GB fp16; 16 GB has wide headroom.
- Estimated wall-clock: Laya arms roughly 1 to 2 h on GPU for the full matrix at
  2 reps; Jev arm about 2,160 calls per sweep (roughly 11M tokens and $0.50 for
  three sweeps over all universes at batch size 1).

## 7. Phases

| Phase | Work | Output |
|---|---|---|
| P0 | bring-up, real tokenizer preflight, truncation freeze, determinism check, noul sanity, telemetry sampler, batch-size spike design | preflight.json, frozen states, telemetry format |
| P1 | Jev batch-1 sweeps, 3 reps (voting), all universes | runs/jev-b1-* |
| P2 | Laya arms B and C, 2 reps (determinism check), all universes; batch-size spike vs ground truth | runs/laya-*, spike report |
| P3 | calibration and accuracy analysis, per arm | analysis + figures |
| P4 | RLCD cybersec fine-tune exercise (Section 8) | fine-tuned checkpoint + validation comparison |
| P5 | comparative paper (PAPER.md here), Lavish review | paper draft |
| v2 | hand-crafted fine-tune dataset expansion (only if P4 shows the model responds) | out of scope now |

## 8. P4: the Jev-labeled RLCD exercise

Purpose: demonstrate that Laya responds to cybersec fine-tuning; not to produce a
near-perfect model. If the response is weak, that is the evidence not to sink time
into hand-crafting a factually correct dataset.

1. Pick one language corpus, JS/TS, and one fairly large public repository.
2. Clone it, run `cavet init` and `cavet scan --deep`.
3. Triage with Jev (the shipped production configuration), recording every
   request/response pair; these pairs are the training signal.
4. Split into train, test, and validation datasets.
5. Fine-tune arm B (typed-decisions, 1024 tokens) with the repo's RLCD recipe on
   the local GPU.
6. Final run on the validation split only, compared against Jev on the same split.

Guardrail: the student trains on Jev's outputs, so it inherits Jev's error modes;
the validation comparison is teacher-versus-student on Jev-labeled data, and the
paper says exactly that.

## 9. Research questions for the paper

- RQ1 (parity): do the open-weights variants (421M typed-decisions and 322M
  multilingual) match the closed vendor model on actionability agreement, recall,
  and precision over identical payloads?
- RQ2 (calibration): whose probabilities are trustworthy against operator labels,
  Jev as-served or Laya raw and temperature-fitted?
- RQ3 (sampling versus determinism): does stochastic sampling with 3-repetition
  voting buy reliability over a single deterministic forward pass, measured as an
  experiment rather than a deployment recommendation?
- RQ4 (economics and hardware): per-finding latency and cost on consumer hardware
  versus a hosted API at equal protocol, with measured CPU, RAM, GPU, and VRAM
  load extrapolated into hardware requirements.
- RQ5 (fine-tuning response): does the model respond to a Jev-labeled cybersec
  fine-tune, and is there evidence justifying hand-crafted dataset investment?

## 10. Risks and guardrails

- Laya's shipped checkpoints are over-confident (raw ECE 0.213 to 0.466 per the
  repo); temperature fitting stays dev-split-only and pre-registered.
- The repo's self-reported numbers are unreproduced; our runs re-measure
  everything on our payloads, which is the point of the study.
- No de-identification change: Laya is local, but corpus-N addressing and the
  no-publication rules of the Jev study carry over unchanged; the P4 repository is
  public code triaged by Jev, so no personal data enters the training set.
- Jev spend is capped by design (about $0.50 for P1 plus the P4 triage of one
  repository); re-check provider pricing before P1 and record it.
- AMD ROCm Windows wheels are a preview stack: the CPU venv stays pinned as the
  same-day fallback, and the determinism check runs on whichever path is active.
