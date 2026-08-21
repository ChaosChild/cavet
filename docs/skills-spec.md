# cavet — Skills Specification

**Status:** Component annex to [`SPECIFICATION.md`](SPECIFICATION.md). Implementation-grade.
**Scope:** the skills component as architecture — residency budget, trigger contracts,
execution sites, CLI dependency contract, install mechanics — plus a gap review of the
drafts in [`skills/`](../skills/), which this annex treats as the source of record for
skill *bodies*.
**Date:** 2026-08-21

The six drafts are good. This annex does not restate them; it specifies everything
around them and records where they need small fixes (§7).

---

## 1. The component

Six skills, hard cap (spec §11): `cavet-design`, `cavet-design-review`,
`cavet-triage`, `cavet-secure-coding`, `cavet-supply-chain`, `cavet-deployment`.
Each is a directory:

```
cavet-<name>/
  SKILL.md          frontmatter + thin body — loaded on trigger
  references/       depth layer — loaded only when named by the body
```

Plus one subagent definition (`subagents/cavet-security.md`) that is not a skill but
shares its contract surface, and one agent-instruction snippet (§6) that is not a
file at all.

**The prefix carries the security signal; names do not repeat it** (spec §11). The
flat namespace makes uninstall = `rm -rf` anything matching `cavet-*`.

---

## 2. Residency budget

The design constraint is near-zero resident cost (spec §1.2). Accounted per skill:

| Layer | When resident | Cost |
|---|---|---|
| Frontmatter (description) | Always, once installed | ~100 tokens each; ~600 for all six |
| Body (`SKILL.md`) | On trigger, for the session turn | 400–900 tokens each |
| `references/*` | On demand, when the body names them | 300–800 tokens per file |

Rules that keep this true:

1. **Bodies never duplicate what the CLI prints** — output shapes live in
   cli-spec §9, not in skill text that would drift.
2. **Depth lives one level down.** A body that needs a table longer than ~25 rows or
   more than ~80 lines total is doing references work.
3. The **only** always-resident spend beyond frontmatter is the instruction snippet
   (§6) — three to five lines in the project's agent instruction file. It exists
   because skill matching is probabilistic and `cavet-design`'s trigger must fire when
   nobody asked (spec §11.1).

---

## 3. Trigger contracts

Descriptions are deliberately pushy and describe *activity*, never security
vocabulary (skills undertrigger by default). Stated as testable contracts:

| Skill | Fires on | Must NOT fire on |
|---|---|---|
| `cavet-design` | Architecture / feature / integration / data-flow / auth / third-party discussion — even casual | Naming, config-file naming, equivalent-parser choice, formatting |
| `cavet-design-review` | Design finalisation: "let's go with this", "write it up", ADR/spec completion, plan approval | Mid-flow brainstorming (that is `cavet-design`) |
| `cavet-triage` | Scan output in context (incl. hook output), "is this safe", pre-commit | Security chatter with no scan result to interpret |
| `cavet-secure-coding` | Any code written or modified — unqualified by design (spec §11.3) | Pure discussion of code not being written |
| `cavet-supply-chain` | Manifest/lockfile change, install/add/update about to run, library comparison | Runtime use of an already-chosen dependency |
| `cavet-deployment` | IaC/Dockerfile/CI files written or changed; hosting decisions | Application code that merely runs in containers |

Calibration obligations live in §8.

---

## 4. Execution sites

| Skill | Site | Why |
|---|---|---|
| `cavet-design` | Parent thread | Conversational; needs operator context |
| `cavet-design-review` | Parent thread | Reads open items; writes `design/` artefacts via operator-visible tools |
| `cavet-secure-coding` | Parent thread | Generation-time: patterns must sit next to the code being written (spec §11.3) |
| `cavet-supply-chain` | Parent thread | Decision support during dependency choices |
| `cavet-deployment` | Parent thread | Same reasoning as secure-coding, applied to IaC |
| `cavet-triage` | **Subagent** (`cavet-security`) + parent reconciliation | Review-time volume isolation (spec §8); parent reconciles against context the subagent lacks |

The split rule in one line: **generation-time work stays in the parent; review-time
volume goes to the subagent; nothing else earns the context churn.**

---

## 5. Contract with the CLI

Normative dependency table (from `install-notes.md`, verified command-by-command
against cli-spec §5):

| Command | Used by | Notes |
|---|---|---|
| `items` | design, design-review | Read-only |
| `raise --kind …` | all except secure-coding | Kind required |
| `resolve` | design, design-review, triage | Closes items |
| `scan` | triage | Subagent-invoked; also reached via hook output |
| `triage` | triage (subagent role) | Verdicts recorded here |
| `lookup` | triage, supply-chain | Identifiers only |
| `defer` | triage | Via verdicts reference |
| `finding`, `log` | *(not named)* | Reached through CLI `next:` hints only |

Style rules enforced across drafts (from `skills/README.md`, restated as contract):

- Command names only, never flags — **one accepted exception**: `(kind: design)` /
  `(kind: verification)` annotations on `raise`. A kindless raise is meaningless, so
  this is disambiguation rather than syntax documentation. Recorded here so the
  exception stays deliberate.
- Every skill tells the agent what to do when unsure: **raise, don't guess** — and
  for the triage subagent specifically, prefer confirm-low over dismiss-low
  (`verdicts.md`).
- Behavioural assumptions the CLI owes the skills (unchanged from install-notes):
  markdown tables with aggregate line and `next:` hints; scanner-set header;
  TTY-gated `engine shell`; tier latencies; de-duplication of already-triaged
  fingerprints.

---

## 6. Install mechanics

1. Skills place as loose directories under the harness's skills path, flat namespace,
   prefix intact. Uninstall = delete `cavet-*`.
2. Subagent definition translates into each harness's format; tool allowlist exactly
   Read + shell scoped to `cavet` (spec §8). No Write, no web — verification gaps
   become parent questions via `verify[n]` blocks, never subagent fetches.
3. The agent-instruction snippet (sole resident spend, verbatim from install-notes):

   ```
   Security is part of design, not a phase after it. When we discuss architecture,
   features, integrations, data flows, auth, or third-party services, surface security
   implications alongside functional ones — one line, at the decision point, via the
   cavet-design skill. When code is written, apply cavet-secure-coding. Before commit
   or on request, run cavet-triage. Never write to .cavet/ directly; the cavet CLI is
   the only author of its log.
   ```

4. First-party installers exist for Claude Code, Codex, OpenCode, Pi, Hermes
   (spec §11.4). Everything else wires up manually against `cavet describe --json`
   (cli-spec §12).

---

## 7. Gap review of the current drafts

Three findings from cross-checking the drafts against spec and annexes. All are small;
none blocks using the drafts today.

### 7.1 `cavet-secure-coding`: runtime self-extension must go

The body says *"Others: add a file when you first work in that stack"* — inviting the
agent to write new `references/<stack>.md` files at runtime. Most harnesses will not
permit writes there, it contradicts the project's own instinct that agents do not hand-
author project artefacts, and silently-grown reference files would escape review.

**Fix:** reword to *"Working in a stack with no file here? Propose the addition to the
operator instead."* New stacks then arrive as reviewed PRs like everything else.

### 7.2 Kind annotations: keep, but record the exception

Done — see §5's accepted exception. No draft change required; this entry exists so a
future style pass does not "fix" it back into uselessness.

### 7.3 Calibration loop needs an owner and a home

Install-notes carries "what to revisit after real use" as prose. Promote it to an
obligation with mechanics (§8 below), because calibration items decay into never when
they are only advice.

---

## 8. Calibration obligations

Ongoing, cheap, non-blocking:

1. **False-flag ledger for `cavet-design`.** Every flag an operator finds noisy gets a
   line in `references/decision-points.md` as a worked negative example. The metric
   that matters is the false-flag rate; negative examples are how the skill learns
   without growing a rules engine.
2. **Stack-reference growth for `cavet-secure-coding`.** Add one language file per
   real encounter, ≤ ~80 lines each (install-notes), via reviewed contribution.
3. **Verification-hint frequency review.** A subagent raising many hints means either
   `verdicts.md` lacks cases or dispatch context is too thin — both fixable, neither
   fixable if unmeasured. Count hints per scan in the surfaced/log data; review monthly.
4. **Trigger-miss review.** When a phase clearly should have fired a skill and did not,
   the description vocabulary gains the missed activity's words. Undertriggering is the
   default failure mode; descriptions are the lever.

---

## 9. Deviations and clarifications against SPECIFICATION.md

1. **Runtime self-extension disallowed** (§7.1) — the draft's "add a file" line is
   superseded; agents propose, operators commit.
2. **Kind annotation exception codified** (§5) — spec §2.1's "skills never document
   CLI syntax" gains its first documented exception, bounded to one flag on one
   command.
3. **Calibration made contractual** (§8) — spec §11.1 asks for negative examples and
   §13.2 asks for a miss log; this annex gives both mechanics and owners instead of
   leaving them aspirational.
