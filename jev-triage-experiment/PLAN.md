# Jev triage experiment: execution plan

> **Experiment only.** This directory lives on branch `experiment/typesafe-jev`
> and is committed for provenance, but it must never reach `main`: if this branch
> is ever merged, drop this directory in the merge. Binaries built for this
> experiment are named `cavet-jev` and are never installed as `cavet`, so agents
> on real projects never pick up an experimentation binary. No PRs from this
> branch. Jev credentials live in gitignored `.env` (`TYPESAFE_API_KEY`) and are
> never committed.

Status: planned 2026-09-20, agreed in a Lavish review session. Local review
artifact (gitignored): `.lavish/jev-triage-spike.html`. Background reading:
*A Gut Feeling With a Type Signature*,
<https://migatchev.co.za/writing/a-gut-feeling-with-a-type-signature>.

## 1. Question

Can TypeSafe's Jev, a System One model that answers narrow questions with typed
answers and probabilities, do a useful first pass over cavet scan findings, and
can its mistakes be made visible, diagnosable and fixable?

Today the scan finishes and a coding-harness agent with the cavet-triage skill
reads every finding. Cost and latency scale with the queue, and most of the
queue is nothing. The hypothesis: a Jev pass answers the cheap relevance
question per finding in milliseconds at a fraction of a cent, and the agent's
attention goes to the pile that matters.

This is research, not a feature build. The deliverable is a comprehensive
report: what we tried, what worked, what did not, what we changed in response,
with the full request/response pairs behind every claim. Taking findings off
the agent's queue (gating) is parked until Jev is publicly available.

## 2. The constraint that shapes the design

Wrong escalations are cheap: a human sees them by definition. Wrong dismissals
are silent: nobody looks. Confidence gating only covers the band where Jev is
unsure; it does nothing about confident-and-wrong, and a calibrated 0.99 is
wrong by design some of the time. Volume turns "some of the time" into a
count. Every stage below is ordered so that measurement is never contaminated
by the thing being measured: in this experiment nothing is ever suppressed,
the agent sees everything, always, and a Jev mistake can cost an incorrect log
line, never a missed vulnerability.

## 3. Ground rules

- Branch `experiment/typesafe-jev`, branched from main at a3df435. No PRs, no
  merges. Binaries as `cavet-jev`, never installed as `cavet`.
- The benchmark corpus is a separate, private benchmark project maintained
  outside this repository. It is a live research site (phase 1 running) and
  strictly read-only from this experiment. Its repos are addressed only as
  `corpus-1` to `corpus-5`. Everything derived from it, including
  request/response pairs and this experiment's report, keeps the corpus-N
  addressing and that project's de-identification rules.
- Every Jev call records the model version actually served (for example
  `jev-1.13.0` for `jev-latest`). `jev-latest` moves underneath us, so gold
  sets re-run on any version change.
- No triage vocabulary in Jev questions. The 2026-09-20 smoke test measured
  Jev splitting 0.72 `not-security` / 0.26 `dismissed` across our own fuzzy
  boundary, so Jev only ever answers "relevant here or not"; verdict words
  stay with the agent.
- Jev state is assembled from scanner metadata and curated project context
  only. Raw adversary-controlled strings (filenames, user agents, commit
  messages) stay out, matching cavet's existing hygiene for the agent.
  TypeSafe's jaggedness page lists adversarial content as a known weak spot.

## 4. Execution ladder

### S0a: shape studio (runs first)

Dataset: a smallish set of real findings drawn from the 2026-09-16 triage pass
(roughly 70 operator-reviewed verdicts in cavet's log). Question shape is
settled before any wide dataset run.

Three call topologies, all against the same labeled findings:

- **A. Single relevance Noul.** One question, one probability, one threshold.
  Simplest to calibrate; one number shows nothing of why.
- **B. Parallel checklist.** Independent Nouls over the same state asked in
  one request (test fixture path? placeholder rather than live value?
  build-time-only dependency? touches auth, crypto or input surface?
  runtime-reachable in the shipped artifact?), combined in code we own. The
  vector of small judgments is the record; a failing case points at a
  question, not the pipeline.
- **C. Sequential cascade.** Call one asks the cheapest decisive judgment;
  findings with a definitive answer (security-confirmed, or clearly inert)
  leave the pipeline there and only the remainder feed the next call with the
  extra context that call needs. Deliberately trades the docs' recommended
  parallel design for per-stage filtering and cheaper later calls. Whether the
  trade pays is a measurement, not an assumption.

Two axes run across all three topologies:

- **Framing:** instruction wording and criteria definitions vary deliberately.
  The model reads literally; the explanation we catch ourselves adding is the
  missing half of the instruction.
- **Output:** bare typed answers versus adding an explicit "missing context
  for accurate determination" signal, to test whether Jev can flag
  insufficient state instead of answering confidently from an incomplete
  picture. The deterministic state builder stays regardless: a missing
  required field is an `if` statement, not a model question.

Protocol: throwaway scripts only, no cavet code changes. Multiple Jev calls
per finding are in budget; calls are fast and cheap. Each variant is measured
against the labels; every dismissal that contradicts a label is a named miss
with its confidence attached; judgments repeat enough to see stability, not
single shots.

Exit: a winning shape is locked, with dismissal FN rate and calibration by
confidence band known.

### S0a outcome and the adopted fast path (2026-09-21)

S0a completed across three shape-studio rounds plus a fresh-init run of all
663 cavet findings (full-run-report.md in this directory: zero actionable
disagreements with recorded operator verdicts). Adopted default: the
two-step cascade (step-1 is_confirmed noul gated at 0.5, step-2 closure
choice for the remainder), mv object state with mechanical enrichment
(path-class prefix rules, fixed source excerpts) and cavet lookup folded
into the enriched state, r3 wording, current_status always open.

Batching study (batch.py, batch-eval.json): grouping by similarity
(source file plus rule-family prefix rule) at batch size 40 keeps 98.6
percent verdict agreement with the single-call run and zero regressions
on the 98 operator-triaged findings, at 66 calls instead of 1323
(95 percent fewer), 0.87M tokens (34 percent fewer), about $0.042, 17.8
minutes wall. Severity grouping is rejected: 87 to 93 percent agreement
with 46 to 86 flips dominated by dismissed-to-not-security boundary
drift. Findings with state_sufficient below 0.3 (the thin-context
image-CVE band) route to the slow single-finding path. Everything
outside the Jev calls is deterministic code: grouping keys, prefix
rules, excerpts, lookup, gates, thresholds. Concurrency was executed the
same day as the second pass: 6 workers over the 33 independent
similarity batches triaged all 663 findings in 255 seconds (4.2
minutes, 5.5x versus the single-call run) at 98.0 percent agreement and
zero operator-triaged regressions.

### S0b progress (2026-09-21)

fragmt (JS): 40 findings through the adopted config in 7 seconds; zero
actionable disagreements against operator verdicts; the not-security
verdict fired on 17 findings, 16 of them in the real served web UI -
valid findings, not security, exactly the intended routing.

Benchmark corpora (scanned sequentially on local scratch copies; the
benchmark tree untouched; finding-level records stay local): 1090
findings total, ground truth confirms 128 of them (95 dependency-SCA
via trivy, 33 opengrep code findings). First pass with a generic
project block collapsed recall on confirmed findings to 25/127
(19.7 percent) - the silent-failure mode this experiment exists to
catch, concentrated in dependency-lockfile SCA findings judged without
project context. The prescribed counterfactual, a mechanically derived
identity-free project archetype ("a Node.js software project that
ships a dependency lockfile") plus a lockfile path-class rule, lifted
corpus-2 recall from 0/87 to 77/87 (88.5 percent), with 78 total
confirmations of which 77 are ground-truth-confirmed. Remaining S0b
work: apply archetype derivation across all corpora, autopsy the
residual misses (10 in corpus-2, 3 near-zero in corpus-4), and fold
archetype detection into the mechanical state builder. All three done
the same day: archetype detection (Go via go.mod, Node via
package.json plus lockfile, Python via pyproject or requirements) and
lockfile path-class rules are now part of the mechanical state builder,
and corpora 3, 4, 5 were rerun with it. Aggregate recall on the 128
ground-truth-confirmed findings: 111/127 = 87.4 percent (from 19.7
percent). Residue, characterised: corpus-2 retains 10 misses (4
info-severity bash findings that are bug-class material, 5 near-gate
SCA at p1 0.35 to 0.47, 1 prototype-pollution at 0.45); corpus-3
retains 1 miss (defused-xml at 0.48, whose confirmation hinged on an
untrusted-feed fact absent from state - the designed escalation band);
corpus-4 retains 2 high-severity misses at p1 0.05 (supply-chain
advisories with no public record, no fixed version, not KEV, no EPSS -
the genuinely hard residue), while its third confirmed finding, which
the operator reconciled as "a bug, not a security issue", was correctly
routed to not-security by the two-step flow. corpus-1 stays clean and
vacuous. Cross-corpus distribution after archetype: 187 confirmed,
852 not-security, 52 dismissed; sufficiency mean 0.27; 115 findings in
the near-gate band route to the human queue by design.

Three further S0b results close the round. First, the severity-blind
counterfactual was adopted into the state builder (severity omitted from
lockfile-finding records plus an explicit instruction that severity is not
grounds for dismissal there): corpus-2 recall 77 to 83/87 (95.4 percent),
corpus-5 31 to 33/34 (97.1 percent), at the cost of one non-ground-truth
confirmation; verification also exposed that source excerpts had silently
been absent from every cross-repo run (the excerpt helper resolved against
the wrong root) - fixed, excerpts now flow, and the corpus-2 and fragmt
results stand validated without them. Second, an independent second-rater
precision check on the over-confirmation set (76 confirmed findings without
ground-truth labels) found only 10 worth confirming: the mass is
audit-class rules in local developer tooling, and the operator's revealed
preference (4 of 475 confirmed on corpus-3, 34 of 270 on corpus-5)
corroborates that Jev's confirmed pile sits above the operator's bar on
that mass. Third, the sufficiency signal was audited for calibration: it
honestly flags "insufficient data" on 97 percent of the starved records
but the distribution is identical on correctly-recalled findings, so today
it is a corpus-level state-quality indicator, not a per-finding router;
recalibration is pending on excerpts actually flowing. Three clean
repetition sweeps of the final configuration (1793 findings x 3 reps, zero
errors) measured consistency: unanimous-status rates cavet 98.5 percent,
fragmt 80.0, corpus-2 100, corpus-3 99.2, corpus-4 100, corpus-5 98.2;
step-1 standard deviation 0.001 to 0.013. All disagreement decomposes into
closure-label noise (dismissed vs not-security) on findings far below the
gate and gate-straddling wobble in the known near-gate band; an A/A rerun
put single-run flip noise at about 1.3 percent, so the operational posture
is three-rep majority voting.

### S0b: expansion rounds

Grow the corpus step by step: more cavet findings, then fragmt findings, then
the benchmark ground truth (operator-reviewed confirmed findings plus a
triage ledger; corpus-1 was fully hand-read and is clean, which makes it a
pure negative set and a direct probe of dismissal bias). Each round re-asks
one question: do the S0a conclusions still hold here? Modify where they do
not, rerun, expand again.

Exit: shape conclusions hold across expansion rounds, or the differences are
understood and documented.

### S1: shadow ride-along

Jev answers with probabilities are written to cavet's append-only log next to
the agent's verdict and, where reviewed, the operator's. Three opinions per
item, disagreement data for free. The agent's queue is untouched.

Exit: live calibration matches the gold-set calibration, and measured cost per
finding is on the record.

### S2: sampling and autopsy

A stratified slice of the dismissed pile is re-judged offline by the agent
with the cavet-triage skill; the operator arbitrates every disagreement.
Sampling cost scales with the sample rate, not scan volume, so coverage can
stay heavy indefinitely. Decided rates (D3): 100% of crit/high dismissals, 50%
of the near-threshold band (p within 0.1 of T), 20% of the far band.

S2 is diagnosis, not audit. "Jev dismissed these three incorrectly, reopen
them" is not the goal; the goal is why, and what would stop it recurring. Every
confirmed miss gets an autopsy: a named cause, a counterfactual change
(instruction wording, criteria, state assembly, decomposition, threshold), and
a retest against both the miss and the full gold set, then adopt or reject the
change with the outcome documented. Metrics: FN rate per stratum with Wilson
confidence intervals, calibration curves, cost per judgment.

Exit: every miss has a documented cause, a tested counterfactual, and a
verdict on whether it generalizes. This exit is the report.

### S3: parked

Gating and scheduling wait for the era when Jev is publicly available. No
numeric gate is defined and none is needed while parked.

## 5. Deliverable and publication

Report artefacts, in the style of the sibling benchmark effort:

| Artefact | Contents |
|---|---|
| Per-judgment records | One machine-readable record per Jev call: full request (state, instructions, criteria), response (answers, probabilities, confidence), model version served, timestamp, corpus and finding reference. Never hand-edited. |
| Aggregate tables | Accuracy and FN rate by corpus and stratum, calibration curves, cost per judgment, per-shape comparison. Generated by script, never typed. |
| Autopsy log | Every miss: ground truth, Jev's answer, named cause, counterfactual change, retest outcome, adopted or rejected. |
| Narrative | Question, corpora, method, results, limitations. The limitations section is not optional. |

Publication ladder (D4, all three, ordered): if anything should be disclosed
to TypeSafe before public posting, that goes first; otherwise a focused
calibration report goes to TypeSafe as early-user feedback. The detailed
report lives in the repo on this branch. A prose article on migatchev-lounge
links to it. If the results look worthy, co-authors and a peer-reviewed
publication are on the table.

## 6. Decision log

| Decision | Outcome | Date |
|---|---|---|
| D1, v0 judgment shape | Nothing picked upfront; the S0 shape studio compares A, B and C plus framing and output axes first | 2026-09-20 |
| D2, gold set | S0b expansion ladder: cavet, then fragmt, then benchmark; verify, modify, rerun each round | 2026-09-20 |
| D3, sampling policy | Hawk: 100% crit/high dismissals, 50% near-threshold, 20% far band | 2026-09-20 |
| D4, report vehicle | All three, ordered: TypeSafe disclosure if needed, calibration report to TypeSafe, branch report, lounge article; peer review possible | 2026-09-20 |
| Batching config | similarity-40 with a thin-context carve-out (state_sufficient below 0.3 routes to the slow path) adopted as the default triage configuration for S0b | 2026-09-21 |
| Next experiment | concurrent similarity-40 batches over 4 to 8 workers; run same day: 255 s for all 663 findings, 98.0 percent agreement, zero triaged regressions | 2026-09-21 |

## 7. Out of scope

Gating and scheduling via serve or cron, parked until Jev is public. Any
non-cavet use of Jev. Changes to the agent's triage skill or verdict
vocabulary. Anything on `main`. Any modification of the private benchmark project. If the
experiment dies at any stage, the residue is a logged dataset and a draft
report, which is the point of a spike.

## 8. References

- TypeSafe docs index: <https://docs.typesafe.ai/llms.txt> (Mintlify pages
  serve Markdown with a `.md` suffix). HTTP API: `POST
  https://api.typesafe.ai/v1/systemone`, bearer auth, `state` + `model` +
  `questions`.
- Article: *A Gut Feeling With a Type Signature*,
  <https://migatchev.co.za/writing/a-gut-feeling-with-a-type-signature>.
- Benchmark methodology (report style borrowed from here): a separate private
  benchmark project, read-only from this experiment.
- Review artifact: `.lavish/jev-triage-spike.html` (gitignored, local only).
