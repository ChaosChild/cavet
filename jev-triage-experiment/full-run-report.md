# S0a final run: fresh-init Jev triage of the entire cavet finding set

Universe: 663 findings (every fingerprint cavet has flagged, remediated excluded). Calls: 1323. Wall: 1411 s. Fresh-init semantics: current_status was open for every finding; state = mv + mechanical enrichment (path class, source excerpt) + cavet lookup; r3 wording; two-step flow with the state_sufficient question.

Methodology note: rounds 1-3 of S0a included the operator verdict as current_status in the mv state for already-triaged findings, so their accuracy numbers are contaminated and only the wording-movement, sufficiency and timing observations stand. This run corrects that.

## Jev's proposal distribution

| status | count |
|---|---|
| dismissed | 608 |
| not-security | 52 |
| confirmed | 3 |

state_sufficient: mean 0.27, min 0.14, max 0.84 (n=663)

## Disagreements with recorded operator verdicts (0)

Operator and Jev disagree on actionable vs not actionable. Each row is a candidate for individual review.

None.

## Agreement summary on triaged findings (98 triaged)

- operator confirmed & Jev confirmed: 3
- operator dismissed & Jev not actionable (dismissed or not-security): 95
- actionable disagreements: 0

## Closure-layer disagreements on curated findings (1)

Both said not actionable, but Jev's closure differs from the suggested mapping (dismissed = security claim wrong here; not-security = valid observation, no security concern). These are arbitration candidates, not errors.

| id | sev | rule | suggested | jev closure | p(not-security) tier |
|---|---|---|---|---|---|
| 6f500b | medium | opt.opengrep-rules.go.lang.correctness.permissions.incorrect-default-permission | not-security | dismissed | 0.72 |

## Untriaged findings Jev would confirm (0)

No operator verdict exists for these; Jev's step 1 crossed the 0.5 gate. Highest-priority review queue.

None.

Untriaged pile: 565 findings carried no operator verdict; Jev proposes the distribution above covers them.
