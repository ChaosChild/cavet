---
name: cavet-triage
description: Interpret security scan findings, separate false positives from real issues, and surface only what matters. Use after code is written or changed, before a commit, whenever scan output appears in context (including pre-commit hook output), when the operator asks to check for vulnerabilities, "is this safe", "run a scan", or asks what to do about a finding. Covers both the isolated triage subagent and the parent session that reconciles its results.
---

# cavet-triage

Scanners produce volume; humans should see judgement. Triage happens in an isolated
subagent so the churn never enters the main session; the parent reconciles the
result against context the subagent does not have. Which role you are in is
determined by how you were invoked: if you were dispatched with a scope and phase,
you are the subagent — read that section only.

## Parent role

**When to scan.** After a meaningful code change, before commit, on request, or when
hook output has landed in your context (a hook result *is* a scan result — treat it
as one, do not re-run it). Not after every keystroke.

**Read the coverage, not just the findings.** The result header names the scanners
that actually ran, and a staged scan runs secrets and dependency checks only — SAST
is not on that path. A clean staged result means "no secrets, no vulnerable
dependencies", never "no vulnerabilities". Say which of the two you mean. When the
change is the kind SAST would catch — parsing untrusted input, building queries or
commands, handling auth — ask for a deep scan rather than reporting the fast one as
clean.

**Dispatch.** Send the security subagent with three things: scope (staged / diff /
full / path), phase (build / test / deploy), and any parent context that bears on
reconciliation — files the operator said not to touch, prior decisions, current
intent. Keep that context to a few lines.

**Receive verbatim.** The subagent returns the CLI's aggregate line, table, next-step
hints, and any `verify` block, unchanged. Do not ask it for a summary; do not
summarise it yourself before reconciling. Prose flattens severity, and severity is
what drives the next step.

**Reconcile.** For each confirmed finding:
- On a file the operator said not to touch → note it, do not act.
- …unless severity is high enough that the earlier instruction deserves revisiting →
  surface it and say why in one line.
- Otherwise → present it, offer remediation, and let the operator or the task decide.

**Answer verification hints.** A `verify` row is a question the subagent could not
answer from code or advisories. You hold operator context and whatever tools the
operator gave you. Answer it from knowledge, look it up, or ask the operator — then
`cavet resolve` the item so the finding's confidence can be raised. If it is not
worth pursuing, say so and leave the item open with that reason.

**Present.** Table as received, then your reconciliation notes. If there is nothing
to show, say "0 new findings" — never silence.

**Remediate** in the parent, with `cavet-secure-coding` loaded. When fixed, the next
scan records it; you do not need to mark it.

## Subagent role

You have Read and the `cavet` binary. Nothing else, by design. You do not fix code,
you do not narrate, you do not paste code into your reply.

**Input.** The dispatch supplies three things:

```
scope: staged | diff <ref> | full | path <p>
phase: build | test | deploy
context: <optional, a few lines — files not to touch, prior decisions, intent>
```

1. Run `cavet scan` for the requested scope and phase (`cavet scan --help` for flags;
   the CLI's own `next:` hints tell you what to run after).
2. For every finding in the table, decide **confirmed** or **dismissed**. To decide,
   read the code at the location — reachability, whether the input is untrusted,
   whether it is a fixture. Category-specific guidance in `references/verdicts.md`;
   read it once at the start.
3. For dependency findings (CVE / GHSA / OSV ids), run `cavet lookup` on the
   identifiers before deciding. Affected range, fixed version, and known-exploited
   status change the verdict; guessing them does not.
4. Record each verdict with `cavet triage`, with a **reason** and a **confidence**.
   Reasons are specific ("test fixture under tests/, not imported by src") not vague
   ("looks fine"). If a lookup influenced the verdict, cite the identifier and URL —
   an uncited lookup did not happen.
5. If a finding turns on a question neither the code nor an advisory answers, do not
   stall and do not guess: triage it `confirmed`, confidence `low`, and run
   `cavet raise` (kind: verification) with the question. Then include it in a
   `verify` block in your reply. The question, never repository content.
6. **Reply with exactly:** the CLI's aggregate line, the table of confirmed findings,
   the `next:` hints, and the `verify` block if any. No introduction, no summary, no
   advice. The parent has the context to decide; you have already recorded
   everything on disk.

Confidence is a real signal. `high` means you would defend the verdict in review;
`low` means "revisit if this file changes or anyone asks". Both are legitimate.
