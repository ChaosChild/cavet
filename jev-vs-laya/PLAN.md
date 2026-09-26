# PLAN: Jev vs Laya, same-payload comparison for security-finding triage

*Draft v1 for operator review (Lavish: `.lavish/jev-vs-laya-design.html`). Branch:
`experiment/jev-vs-laya`, cut from `experiment/typesafe-jev` at cf88ca2. Harness is
imported from `../jev-triage-experiment/` unchanged; everything new lives here.*

## 1. Premise

The Jev evaluation (concluded 2026-09-23, branch `experiment/typesafe-jev`) measured
TypeSafe's closed System One model as a first-pass triage filter over 1,793 findings
from seven universes. Laya (convaiinnovations/laya, Apache 2.0) is an open-weights
System 1 decision engine: same typed-question paradigm (`choice`, `score`, `noul`),
same calibrated-probability response shape, 421M parameters, single forward pass.
Laya even speaks Jev's wire protocol (`POST /v1/systemone`). Laya's own benchmark
admits its Jev numbers are third-party and never same-payload. This study closes
that gap: **byte-identical states and questions, the same gate, the same gold sets,
two models, one deterministic and one stochastic.**

What is new here relative to the Jev paper:

1. The first same-payload head-to-head between a closed and an open System One model.
2. A calibration suite (Brier, ECE, NLL, AUROC against operator labels) that the
   Jev paper never measured.
3. A determinism contrast: Jev samples (5-repetition voting, A/A flip rate 0.75 to
   1.2 percent) versus Laya's single deterministic forward pass.
4. Consumer-hardware economics: $0 marginal cost on a 16 GB AMD GPU versus $0.042
   per million tokens hosted.

## 2. Arms

| Arm | Model | Context | Reps | Purpose |
|---|---|---|---|---|
| A | Jev jev-1.13.0, batch size 1 | large (134 KB bodies accepted) | 5 | closed-vendor reference at parity config |
| B | convaiinnovations/laya-typed-decisions | 1024 tokens | 2 (determinism check) | primary open-weights arm |
| C | convaiinnovations/laya-multilingual, max_len 8192 | 8192 tokens | 2 | open-weights arm, no truncation |
| D (optional) | convaiinnovations/laya (English root) | 512 tokens | 2 | context-starvation probe |

Notes.

- Arm A uses batch size 1 everywhere for payload parity; the shipped batch-40
  configuration stays as measured in the Jev paper. The cavet universe already has
  one batch-1 sweep (the fresh-init run, 1,323 calls, 1,411 s); fresh sweeps run
  all five repetitions for uniformity.
- Arm D is a diagnostic, not a headline arm: the preflight (Section 6) estimates
  roughly 8 percent of cavet states exceed 512 tokens, so it measures what state
  truncation costs, mirroring the archetype/context-starvation finding of the
  Jev study.
- Own RLCD cybersec fine-tune: **deferred to a possible v2**. It needs new ground
  truth (scan a handful of large repos with cavet, hand-triage each), which the
  operator is not committing to yet. Kept on the cards; not part of this study.

## 3. Protocol (parity decisions)

1. **Byte-identical payloads.** The state builder (`harness.state_mv`, fresh-init
   semantics) and the two-step cascade (`is_confirmed` noul gate at 0.5,
   `state_sufficient` ride-along, step-2 closure choice between *dismissed* and
   *not-security*) run unchanged. Laya receives the exact same JSON state and
   question objects. States are rebuilt once from the existing details caches and
   frozen to disk before any arm runs.
2. **Gate and voting unchanged.** Step-1 gate at 0.5; majority status is the
   operational answer. For Jev, five repetitions vote. For Laya, inference is
   deterministic (single encoder forward pass, eval mode): repetitions are identical
   by construction, so each Laya arm runs twice as a determinism check, and the
   paper reports the sampling-versus-determinism contrast as a result, not a bug.
3. **Same universes, same labels.** All seven universes (cavet 663, fragmt 40,
   corpus-1 zero control, corpus-2 337, corpus-3 475, corpus-4 8, corpus-5 270)
   with the gold sets of the Jev study, unchanged.
4. **Laya deviations handled, documented.** Choice cap 100 (our closure has 2
   options), state cap 50,000 characters (ours peak at 8.1 KB), `usage.output_tokens`
   always 0, extra response fields ignored, unknown `model` ids silently rerouted
   (we pass explicit checkpoint ids and verify the echo per response).

## 4. Calibration (new measurement)

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

## 5. Runtime (validated 2026-09-26)

- Hardware: local AMD Radeon RX 9060 XT 16 GB (RDNA 4, gfx1200), Windows 11.
- Primary path: native Windows venv with AMD's ROCm preview PyTorch wheels
  (torch 2.13 from the gfx120X index, Adrenalin 26.8.1); CPU venv alongside as the
  zero-risk fallback (full sweep roughly a day, pin interop threads to 1).
  WSL2 ROCm is the production-grade alternative; ONNX DirectML is plan C;
  torch-directml is not viable. Laya's TileLang fast path is CUDA-only and unused.
- All three checkpoints resident: about 2.3 GB fp16; 16 GB has wide headroom.
- Laya arms are driven through the library (`predict_batch`) rather than
  `laya-serve` (single worker, 503 above 16 concurrent); every judgment still
  recorded as a request/response pair in the same run-file format.
- Estimated wall-clock: Laya arms 1.5 to 3.5 h on GPU for the full matrix;
  Jev arm about 3,600 calls per sweep (roughly 18M tokens and $0.75 for five
  sweeps over all universes at batch size 1).

## 6. P0 preflight (before any arm runs)

1. Download the three checkpoints; smoke-test one finding per checkpoint on CPU.
2. Tokenize all 1,793 frozen states with each checkpoint's real tokenizer; record
   the true distributions. Preflight estimate on cavet (chars/4): median 394,
   p95 591, max 2,031 tokens; over 512: 8.0 percent; over 1024: 0.2 percent.
3. Freeze the truncation policy per checkpoint: state budget = max_len minus the
   question/head budget; truncation order is cavet_lookup first, then
   source_excerpt tail, never the finding core; identical policy in every Laya
   arm; truncation incidence reported per universe.
4. Determinism check: run one batch of 20 findings twice per checkpoint; require
   identical outputs (bit-equal probabilities) before adopting the 2-rep protocol.
5. Noul sanity: confirm binary noul does not exhibit the documented
   label-following failure (our questions are yes/no; the closure is a 2-option
   choice, inside Laya's safe cardinality zone).

## 7. Phases

| Phase | Work | Output |
|---|---|---|
| P0 | bring-up, tokenizer preflight, truncation freeze, determinism check | preflight.json, frozen states |
| P1 | Jev batch-1 sweeps, 5 reps, all universes | runs/jev-b1-* |
| P2 | Laya arms B, C, (D) over all universes | runs/laya-* |
| P3 | calibration and accuracy analysis, per arm | analysis + figures |
| P4 | comparative paper (PAPER.md here), Lavish review | paper draft |
| v2 | own RLCD cybersec fine-tune (deferred, needs new labeled repos) | out of scope now |

## 8. Research questions for the paper

- RQ1 (parity): does the open 421M model match the closed vendor model on
  actionability agreement, recall, and precision over identical payloads?
- RQ2 (calibration): whose probabilities are trustworthy against operator labels,
  Jev as-served or Laya raw/fitted?
- RQ3 (sampling versus determinism): does stochastic sampling with 5-repetition
  voting buy reliability over a single deterministic forward pass?
- RQ4 (economics): per-finding latency and cost on consumer hardware versus a
  hosted API, at equal protocol.
- RQ5 (context): what does a 512-token state budget cost in accuracy (arm D),
  and does it reproduce the context-starvation failure classes of the Jev study?

## 9. Risks and guardrails

- Laya's shipped checkpoints are over-confident (raw ECE 0.213 to 0.466 per the
  repo); temperature fitting stays dev-split-only and pre-registered.
- The repo's self-reported numbers are unreproduced; our runs re-measure
  everything on our payloads, which is the point of the study.
- No de-identification change: Laya is local, but corpus-N addressing and the
  no-publication rules of the Jev study carry over unchanged.
- Jev spend is capped by design (about $0.80 for the arm); if the provider's
  pricing changed since September 23, re-check before P1 and record it.
