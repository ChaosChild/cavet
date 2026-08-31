# cavet — Design Specification

**Status:** Specification revised against measured scanner behaviour. Nothing built yet.
**Name:** `cavet` — from *caveat*, "let him beware". A warning, not a prohibition.
**Licence:** MIT
**Language:** Go
**Date:** 2026-08-17 (revised 2026-08-18, 2026-08-21)

The revisions of 2026-08-21 follow from the [scanner-baseline
spike](https://migatchev.co.za/projects/cavet) (formerly
`spike-2026-08-21-scanner-baseline.md` in this directory), which
captured real output and timings from Opengrep 1.27.1, Gitleaks 8.30.1 and Trivy
0.74.0. Where this document previously asserted something the measurements
contradict, the measurement wins and the section says so.

---

## 1. Purpose

A toolbox that lets a **willing operator** enable their coding agent to think about
security while it works, and to deal with the results efficiently — without the
operator prompting for it every time.

The problem it solves: security review currently happens only when you remember to
ask, and what you get back is whatever the model improvises that session — different
depth, different coverage, different format, no memory of last time.

`cavet` makes it **repeatable**: the same checks, the same phases, the same output
shape, the same audit trail, session after session.

### 1.1 What this is not

- **Not a gate.** Nothing blocks. Everything advises. The agent or the operator
  chooses to remediate, defer, or dismiss.
- **Not an enforcement mechanism.** Teams that need enforcement build it themselves
  around these tools. Out of scope, stated plainly in the README.
- **Not a guarantee of secure code.** It is a toolbox, not an outcome.
- **Not a harness compatibility layer.** Installers ship for a handful of popular
  harnesses (§11). Beyond that, operators wire it up themselves against a documented
  machine contract.
- **Not a scanner.** Every deterministic check is an existing open-source tool.
  `cavet` owns orchestration, output ergonomics, memory, and judgement — not
  detection engines.

### 1.2 Design constraints

1. **Near-zero resident context cost.** Nothing loads until needed.
2. **Cross-platform.** Windows, macOS, Linux. Windows is the primary development
   platform and is not a second-class target.
3. **Harness-agnostic core.** The CLI works anywhere a shell does, including
   harnesses that reject MCP.
4. **Deterministic where deterministic is possible; judgement where it isn't.**
5. **Everything leaves a trace.** No decision disappears when the session ends.

---

## 2. Architecture

Four components with sharply different residency costs:

| Component | Resident cost | Owns |
|---|---|---|
| **CLI** (`cavet`, Go binary) | 0 tokens | Orchestration, fingerprinting, state, log, output shaping, path translation |
| **Engine** (OCI container) | 0 tokens | Scanner execution, git, pinned tool versions |
| **Skills** | ~100 tokens each (frontmatter only) | Judgement: when to act, how to read results, what's acceptable, what's next |
| **Artefact directory** (`.cavet/`) | 0 tokens | Memory: the shared spine every component reads and writes |

Plus one optional operator-installed trigger (§9) and one subagent contract (§8).

### 2.1 Division of responsibility

The CLI owns **how** — flags, syntax, next-step hints emitted in its own output.
Skills never document CLI syntax; that drifts and duplicates what `--help` answers
for free at the moment of need.

Skills own **when to reach for it, how to interpret what comes back, what is
acceptable risk in this context, and what to do next.** That is the part no tool can
emit.

### 2.2 Deliberately excluded

- **MCP server.** Schema overhead is paid on every turn of every session whether or
  not anything is scanned. A CLI costs nothing until invoked and works in harnesses
  that reject MCP. Revisit only if a target harness gains no shell access.
- **Agent Plugins 1.0 manifest.** Not needed now. Add later for catalogue
  discoverability if worthwhile — it is a wrapper around skills that will already
  exist.
- **Design-phase CLI commands.** Design is conceptual. There is nothing deterministic
  to run. Skills only.
- **Git credentials in the container.** See §7.3.

---

## 3. The artefact directory

Lives at `.cavet/` in the repository root. **Committed to version control.** This
makes decisions reviewable in a diff and carries them across sessions, machines, and
agents.

```
.cavet/
  config.yaml              # operator configuration
  .gitattributes           # log/*.jsonl merge=union
  .gitignore               # state/, cache/, reports/
  log/
    events-2026-08.jsonl   # append-only, monthly rotation — committed
  state/                   # derived, gitignored, `cavet rebuild` regenerates
    findings.json          # currently open findings, with last_seen per fingerprint
    items.json             # open items — design concerns, verification requests
    baseline.json          # pre-existing debt recorded at init
  cache/
    advisories/            # derived: lookup results, gitignored
  design/
    threat-model.md        # produced by design skills — committed
    decisions/             # security decision records (ADR-shaped) — committed
  reports/                 # derived, gitignored
    latest.sarif           # machine interchange for CI / code scanning
```

**What is committed:** `config.yaml`, `log/`, `design/`. Everything else is derived
and gitignored — committing it would guarantee merge conflicts for no benefit, since
`cavet rebuild` recreates it from the log in well under a second.

**Concurrent branches.** Two branches that both append to the same monthly log file
conflict at end-of-file under git's default merge. `cavet init` writes a
`.gitattributes` setting `merge=union` on `log/*.jsonl`, which is correct for
append-only line-oriented files: both sides' lines are kept, order within the file is
irrelevant because every event carries its own timestamp, and `cavet rebuild` after a
merge reconciles state. Duplicate events (the same fingerprint `detected` on both
branches) are harmless and collapse on rebuild.

Note there is no `tools.lock` — the engine image digest in `config.yaml` serves that
purpose (§7.2).

### 3.1 The log is the source of truth

`log/` is **append-only** and authoritative. Everything in `state/` is a derived
cache, regenerable with `cavet rebuild`.

Three reasons this matters: append-only files produce clean, readable diffs; nothing
can desync state from history; and "why was this dismissed three weeks ago" always has
an answer.

**Event schema** (JSONL, one object per line):

```json
{
  "ts": "2026-08-17T09:14:22Z",
  "event": "triaged",
  "fingerprint": "a3f9c2...",
  "actor": "agent",
  "phase": "build",
  "engine": "ghcr.io/chaoschild/cavet-engine@sha256:...",
  "data": { "verdict": "dismissed", "confidence": "high",
            "reason": "test fixture, not reachable from production code" }
}
```

**Event types:**

| Event | Meaning |
|---|---|
| `detected` | A scanner reported a finding for the first time (one per fingerprint, not per scan — re-observations update `last_seen` in `state/`, not the log) |
| `triaged` | Assessed — `confirmed` \| `dismissed`, with reason and confidence |
| `surfaced` | Presented to the operator |
| `remediated` | Code changed; finding no longer reproduces. Emitted only when the finding's originating **scanner ran in this scan** and the finding's path was in scope, and the finding is absent. Absence from a scan that did not cover the file, or did not run the scanner that found it, is not remediation (§5.2) |
| `suppressed` | Deliberately silenced, with reason |
| `deferred` | Acknowledged, not now |
| `raised` | An open item created — a design concern or a verification request (`kind` discriminates) |
| `resolved` | An open item closed, with the decision or answer |
| `rebaselined` | Engine image changed; baseline regenerated |

`actor` is `agent` or `operator`. Both write to the same log.

**Data fields by event.** The `data` object is event-specific and its shape is owned by
the `events` package:

| Event | `data` fields |
|---|---|
| `detected` | `rule`, `severity`, `path`, `line`, `description`, `scanner`, `also_detected_by[]` |
| `triaged` | `verdict` (`confirmed` \| `dismissed`), `confidence`, `reason`, `sources[]` |
| `surfaced` | `context` |
| `remediated` | `reason` |
| `suppressed` | `reason` |
| `deferred` | `reason` |
| `raised` | `kind` (`design` \| `verification`), `question`, and for `verification` the `fingerprint` of the finding it concerns |
| `resolved` | `answer`, `sources[]` |
| `rebaselined` | `from_digest`, `to_digest`, `reason` |

`sources[]` carries the identifiers and canonical URLs behind a decision (§5.3).

**Implementation note:** all event construction lives in a single `events` package
with typed constructors. No raw string literals for event types, verdicts, severities,
or phases anywhere else in the codebase. This is the discipline that substitutes for
sum types in Go (§10.2).

### 3.2 Nothing is silently discarded

Every finding a scanner produces gets a `detected` event on first sight, including
the ones the subagent dismisses as false positives seconds later. Subsequent scans
that see the same fingerprint do not re-emit it — that would make a full scan of a
repository with 347 baseline findings write 347 events every time — but they do
refresh `last_seen` in `state/`, so "is this still present" is answerable without a
scan. The operator never sees most of
them (§6), but three weeks later "did we see this before, and why did we drop it?" is
always answerable.

This is the single most important property of the design. It is what makes agent-side
triage acceptable.

### 3.3 Fingerprinting

Findings need identity that survives ordinary code movement, or the audit trail breaks
and everything gets re-triaged forever.

**Fingerprint = `sha256(rule_key + normalised_code_context)`**

- `rule_key` is the rule's CWE identifier where the scanner supplies one, falling back
  to the scanner's rule id. Engine bumps rename and renumber rules; CWE mappings are
  stable. Hashing on `rule_id` alone would discard every dismissal on the next
  `rebaseline`, since rebaseline regenerates the baseline but must not fabricate
  triage history.
- Normalised context: the matched span plus limited surrounding lines,
  whitespace-collapsed, string and numeric literals masked.
- **Path is not part of the fingerprint.** A moved or renamed file keeps its finding
  and its triage history.
- Consequence: the same pattern in two files is **one finding with two locations**,
  and a triage verdict applies to both. This is the intended reading — a dismissal is
  a judgement about a pattern, and if the two occurrences genuinely differ the
  surrounding context differs and so does the hash.
- Paths are recorded as mutable metadata on the finding, plural.
- Changing the code changes the fingerprint — a dismissal does not survive a rewrite
  of the code it was about. Correct behaviour, not a bug.

**The originating scanner is recorded per fingerprint** in `state/findings.json`, not
only in the `detected` event. `remediated` cannot be decided without it (§3.1), since
a scan that did not run a given scanner proves nothing about that scanner's findings.

**Cross-scanner duplicates.** Gitleaks and Trivy's secret scanner overlap, and both
run on the fast path (§5.2). Measured against the same repository, both reported the
same Slack token under different rule ids — `slack-bot-token` and
`slack-access-token` — and neither carried a CWE, so `rule_key` falls back to the
scanner's rule id and the fingerprints diverge. Two findings for one secret means two
triage decisions for one judgement, which is exactly what §3.3 exists to prevent.

Secrets are therefore collapsed **before** fingerprinting, on
`sha256(normalised_matched_span + path)`. The first scanner's rule id is kept, the
other is recorded in `also_detected_by[]`, and one fingerprint is produced. Both
attributions survive in the log; only one triage is ever asked for.

This applies to secret findings specifically. SAST and SCA findings do not overlap
across the default scanner set, and inventing a general cross-scanner identity for
them would be speculative — revisit if a second SAST engine is ever enabled.

### 3.4 Determinism of the delta

If scanner rules or vulnerability databases drift between runs, the delta becomes
noise and stops being trustworthy.

The engine image digest solves this by construction. One pinned digest is one exact
set of scanner binaries, rule sets, and bundled vulnerability data — reproducible on
any machine, on any architecture.

- The digest is pinned in `config.yaml` and recorded on every event and report.
- Changing it is an explicit operation (`cavet rebaseline`) that emits a
  `rebaselined` event and regenerates the baseline.
- Offline and proxied environments are supported paths, not afterthoughts (§7.5).

---

## 4. Output ergonomics

Findings data is close to a worst case for agent context: SARIF is deeply nested,
enormously repetitive, and its location objects are often longer than the findings
they describe.

Measured, this is worse than it sounds. An Opengrep run producing **7 findings**
emitted 889,143 bytes of `tool.driver.rules` metadata against 5,555 bytes of actual
`results` — **99.4% of the document describes rules that did not match**. Gitleaks
emits ~50KB and 222 rule descriptors for a single finding. A full-corpus run reached
2.6MB for 10 findings.

**Raw SARIF never reaches the model.** It is written to `reports/` for CI and code
scanning. The agent sees a compact projection.

The projection reads `results[]` and consults `tool.driver.rules` only to resolve the
matched `ruleId`. Nothing else in the document is loaded, and the size of the
unmatched-rule metadata is therefore irrelevant to context cost.

**Output format: GitHub-flavoured markdown tables.** Readable by agents and humans
without a rendering step, pasteable into an issue or a PR comment unchanged, and
diffable. Revisit against more compact encodings after real-world use, not before.

Principles adopted (from AXI, selected on merit rather than wholesale):

1. **Markdown tables** on stdout, one row per finding.
2. **Minimal default columns** — id, severity, rule, location, one-line description.
   Everything else behind `cavet finding <id> --full`.
3. **Pre-computed aggregates** — severity counts and the delta-vs-baseline summary
   above the table, so the agent never round-trips to work out what it is facing.
4. **Definitive empty state** — an explicit "0 new findings", never silence.
5. **Contextual next-step hints** below the table as concrete command templates with
   placeholders, so the agent does not burn a turn on discovery.
6. **Structured errors, clean exit codes**, no interactive prompts ever, unknown
   flags fail loud.
7. **Content-first** — bare `cavet` prints current posture, not help text.

Exit codes are informational, not gating: `0` clean, `1` findings present, `2` usage
or execution error.

### 4.1 Reference output

```
scan: staged · scanners: gitleaks,trivy · phase: build · engine: cavet-engine@sha256:4f2a…
2 confirmed (1 high, 1 medium) · 14 dismissed · 0 new suppressions · baseline 347

| id     | sev    | rule                 | location            | description                          |
|--------|--------|----------------------|---------------------|--------------------------------------|
| a3f9c2 | high   | py.sql-injection     | api/users.py:88     | user input concatenated into query   |
| 7b1e04 | medium | generic.weak-hash    | auth/tokens.py:23   | MD5 used for token derivation        |

next:
  cavet finding a3f9c2 --full
  cavet log --fingerprint 7b1e04
```

**The header names the scanners that actually ran.** Because the scanner set varies
with scope (§5.2), a clean result is ambiguous without it — an agent must be able to
distinguish "nothing was found" from "SAST did not run". This is the empty-state
principle applied to coverage rather than to findings.

---

## 5. CLI surface

```
cavet                               # posture home view
cavet init [--hooks]                # scaffold .cavet/, pull engine, baseline debt
cavet scan [--staged|--diff <ref>|--full] [--deep] [--phase <phase>]
cavet finding <id> [--full]
cavet triage <id> (--confirm|--dismiss) --reason "..." [--confidence high|low]
cavet suppress <id> --reason "..."
cavet defer <id> --reason "..."
cavet raise --kind (design|verification) --question "..." [--fingerprint <id>]
cavet resolve <item-id> --answer "..." [--source <url>]...
cavet debt [--severity <level>]     # pre-existing baseline, on demand only
cavet log [--since <date>] [--fingerprint <id>]
cavet lookup <identifier>... [--refresh]   # advisory / rule lookup, allowlisted sources
cavet items                         # open items: design concerns + verification requests
cavet engine (status|start|stop|pull|shell)
cavet rebuild                       # regenerate state/ from log/
cavet rebaseline                    # after a deliberate engine image change
cavet describe --json               # machine contract for third-party installers
```

`describe --json` emits skill paths, recommended subagent tool allowlists, trigger
commands, engine digest, and version metadata — so people writing installers for
harnesses `cavet` does not support read a stable contract instead of scraping
documentation.

`raise` and `resolve` are how skills write open items (§8.1, §11.1). They are the
only path — no component writes to `log/` except through the binary, so the `events`
package (§10.2) is the sole author of every line.

`engine shell` drops the operator into the container for debugging. Not for agent use:
it refuses to start when stdin is not a TTY, so a subagent allowlisted on `cavet *`
cannot reach it.

### 5.1 First-run behaviour

`cavet init` pulls the engine image, starts the container, scans, records everything
found as `detected` events, writes `state/baseline.json`, and reports:

```
initialised. 347 existing findings recorded as baseline.
run `cavet debt` when you want to work through them.
```

**The baseline scan is always a full-tier scan** (§5.2), regardless of how long it
takes. A baseline built from the fast tier would omit every SAST finding, and each
one would then arrive as a spurious `detected` event on the operator's first
`--full` — presented as new work when it is pre-existing debt. Getting this wrong
inverts the entire purpose of §5.1.

Day one shows the operator **only what happens next**. Pre-existing debt is available
on demand and never dominates a scan result. A wall of 347 findings on first run is
how this tool gets uninstalled in week one.

### 5.2 Scan tiers and latency

**SAST is not on the fast path.** An earlier draft budgeted ≤ 10 seconds for a staged
scan across all three scanners. Measurement showed that to be unreachable: Opengrep's
cost is rule *parsing*, paid on every invocation and almost independent of how many
files are scanned.

| Rules loaded | Files scanned | Time |
|---|---|---|
| 2 | 3 | 2.9s |
| 368 (one language) | 1 | 10.8s |
| 368 (one language) | 5 | 12.6s |
| 962 (all languages) | 1 | 48.4s |
| 962 (all languages) | 5 | 49.1s |

One file costs what five files cost. A warm container does not help — repeated
`docker exec` measured 11.5s then 11.2s. The floor is ~2.2s of Opengrep's own startup;
above that, roughly 26–48ms per rule, degrading superlinearly.

Rather than curate the ruleset down to fit a budget — trading coverage for a number,
and taking on permanent curation work — the budget moves to where it is actually
achievable, and SAST becomes an explicit operation.

**Scope implies the scanner set:**

| Invocation | Scanners | Warm cost |
|---|---|---|
| `scan --staged`, `scan --diff <ref>` | Gitleaks + Trivy | **~1.8s** |
| `scan --full` | Gitleaks + Trivy + Opengrep | ~50s |
| `scan --staged --deep` | all three | ~50s |

`--deep` is the single override, for the operator who wants SAST on a staged scan and
will wait for it; `config.yaml` can make that the default per repository. There is no
`--fast` and no `--no-deep` — `--full` is already how you ask for everything.

The fast tier is comfortably better than the 10 seconds originally budgeted, which
makes the §9 pre-commit trigger genuinely unnoticeable. Deep scans belong to `--full`,
to CI, and to explicit request.

**Consequences elsewhere.** The scanner set is printed in the result header (§4.1), so
a clean result is never ambiguous about coverage. `remediated` is gated on the
originating scanner having run (§3.1, §3.3). The baseline is always built deep (§5.1).

**Staged means the index, not the working tree.** Scanners read files on disk, and the
working-tree version of a staged file may differ from what is staged. The CLI runs
`git checkout-index` for the staged paths into a temporary directory inside the
container and scans that, so the result describes what will actually be committed.
Paths are translated back to repository-relative locations in the output.

**The bind mount is the other variable.** Docker Desktop file sharing on macOS and
Windows is markedly slower than native, and a repository on the Windows filesystem
accessed from the WSL2 backend is the worst case. Measure on Windows on day one, and
document that repositories living inside the WSL2 filesystem scan considerably faster.

### 5.3 Lookup

Scanner rule descriptions are frequently terse or stale, and CVE and GHSA identifiers
carry almost no meaning on their own. Deciding whether an advisory matters here needs
the affected version ranges, the fixed version, and whether the vulnerability is known
to be exploited. A subagent guessing at that is worse than one that looks it up.

`cavet` owns the lookup rather than delegating it to the agent's web tooling. This is
a security decision before it is an ergonomic one: a command whose only parameters are
identifiers **cannot** leak repository content, because there is no argument that could
carry a code snippet, a file path, or a secret value. As an instruction to a subagent,
that constraint is policy; as a CLI signature, it is structural.

**Inputs.** CVE, GHSA, and OSV identifiers; package coordinates
(`pkg:npm/lodash@4.17.20`); scanner rule identifiers; CWE references. Nothing else is
accepted.

**Sources**, allowlisted in code rather than configuration:

| Source | Provides | Auth |
|---|---|---|
| **OSV.dev** | Advisory data across ecosystems, affected ranges, fixed versions | None |
| **CISA KEV** | Known-exploited status | None |
| **EPSS** | Exploitation probability score | None |
| **Package registries** | Version existence, deprecation, maintenance status | None |
| **NVD** | CVSS vectors, supplementary detail | Optional API key |

Rule metadata is **not** a network operation. Opengrep and Semgrep rules carry their
message, CWE mapping, references, and confidence inside the rule definition, which
already ships in the engine image. `cavet lookup <rule-id>` reads it locally.

**Output** is a compact markdown table carrying only what changes a triage decision —
severity, affected range, fixed version, known-exploited flag, EPSS score, one-line
summary, canonical URL. Not the full advisory prose.

**Execution site.** Lookup runs in the Go CLI on the host, never inside the engine
container. This keeps the container offline-capable by design (§7.5) and keeps
third-party scanner code away from network egress. The network-facing surface stays
small and auditable.

**Caching.** Results are cached in `.cavet/cache/advisories/`, gitignored because they
are derived and would otherwise bloat diffs. Repeat triage of the same identifier is
free and works offline. `--refresh` forces revalidation. Cache entries carry a fetched-at timestamp
and expire after **one week** — long enough that ordinary triage is cache-served,
short enough that a newly-published fix or a change in known-exploited status is picked
up while it still matters.

**Enrichment at scan time** draws from cache only, so the fast tier (§5.2) is never
spent on network I/O. Uncached identifiers are marked as such and resolved on
demand.

**Degradation.** No network, an unreachable source, or a rate limit produces an
explicit "not available" marker on the affected row — never a silent omission, and
never a hard failure. Triage proceeds with less evidence and records that it did so.

**Maintenance is a project obligation.** Five external APIs are five things that can
drift, rate-limit, or disappear. Shipping lookup in the binary means owning that; it is
not a cost to be discovered later. The client surface stays deliberately thin — one
adapter per source, no shared abstraction — so a source that breaks is a contained
repair. A source that begins requiring authentication is a candidate for removal rather
than a reason to start handling credentials.

---

## 6. Triage

The subagent carries the triage burden. The operator does not.

Scanners produce large volumes of false positives; passing them to a human defeats the
purpose. Agent dismissal is acceptable **only** because §3.2 guarantees nothing
vanishes.

**Rules:**

- Every finding gets a `detected` event before any triage.
- Every dismissal carries a **reason** and a **confidence**. "Dismissed, low
  confidence" is a materially different thing to revisit later than "dismissed,
  obviously test fixture data" — the distinction must be recorded.
- Only `confirmed` findings are surfaced to the operator by default.
- `cavet log --fingerprint <id>` reconstructs the full history of any finding.

### 6.1 Reconciliation by the parent

The subagent returns findings; the parent session holds context the subagent lacks
(operator instructions, prior decisions, current intent). The parent reconciles:

- Finding on a file the operator said not to touch → note it, do not act.
- …unless severity is high enough that the earlier decision deserves revisiting →
  surface it and say why.

This only works if the subagent returns exact structured data (§8). Prose summaries
flatten severity first, which kills exactly the escalation path that matters.

---

## 7. The engine

A single OCI image containing every scanner, plus `git`. The CLI never assumes any
scanner exists on the host.

**Why:** the image digest gives reproducibility by construction (§3.4); scanner
runtimes (Python, OCaml, Go) never touch the operator's machine or the CLI build;
multi-architecture support is a build-matrix concern rather than a per-tool porting
problem; and a future version can point at a remote Docker host for teams that want
scanning offloaded to bigger infrastructure.

**Plain OCI only.** No Compose, no Docker-specific features, so `podman` works
unchanged. That is the escape hatch for organisations where Docker Desktop licensing
is a problem, and it costs nothing to preserve now.

The CLI talks to the Docker API through the official Go SDK rather than shelling out
to the `docker` binary — no PATH dependency, structured errors, clean lifecycle
control.

### 7.1 Lifecycle

**One long-lived container per repository**, not one per scan.

The justification is Trivy, and it is larger than the container-startup cost this
section originally cited. Measured across repeated `docker exec` into one warm
container:

| Scanner | First run | Subsequent |
|---|---|---|
| Trivy | 24.0s | **1.2s** |
| Gitleaks | 0.7s | 0.6s |
| Opengrep | 11.5s | 11.2s |

Trivy improves 20× once its caches are warm, and Trivy is on the fast path (§5.2), so
the long-lived container is what makes the fast path fast. Gitleaks was never slow.
Opengrep gains nothing — its cost is per-invocation rule parsing, not process or cache
warm-up — which is a further reason SAST does not belong on the fast path.

- `cavet init` starts it, workspace mounted.
- Each scan is a `docker exec` into the running container — marginal cost near zero.
- The CLI health-checks before each scan and restarts transparently if the container
  has stopped.
- `cavet engine stop` tears it down. There is no idle timeout: an idle container
  holds some memory and effectively no CPU, and stopping it would reintroduce the 24s
  Trivy cold start the fast tier (§5.2) depends on avoiding. Operators on
  constrained machines can bound it with ordinary Docker resource limits.

### 7.2 Contents

| Capability | Tool | Licence | Notes |
|---|---|---|---|
| SAST | **Opengrep** | Engine LGPL-2.1; **rules LGPL-2.1 + Commons Clause** | Default engine, deep tier only (§5.2) |
| Secrets | **Gitleaks** | MIT | Requires git history |
| SCA, IaC, containers | **Trivy** | Apache-2.0 | One binary, one startup. Container image scanning is a separate opt-in (§7.6) |
| IaC *(optional, off by default)* | **Checkov** | Apache-2.0 | Enabled per repository in `config.yaml`; broader IaC coverage than Trivy at a real startup cost |
| VCS | **git** | GPL-2.0 | Read operations, sandboxed |

**Three default scanners, not five.** Trivy covers dependency scanning, IaC
misconfiguration and container images from one Go binary with one process start, which
is what makes the fast tier (§5.2) achievable. It replaces OSV-Scanner outright.
Checkov stays in the image for operators who want its wider IaC rule set — it is a
`config.yaml` switch, off by default, and its cost is paid only by those who choose it.

**Opengrep's rules are not LGPL, and an earlier draft of this document was wrong to
say so.** `opengrep-rules/LICENSE` reads:

```
"Commons Clause" License Condition v1.0
... the License does not grant to you, the right to Sell the Software.
Software: semgrep-rules (https://github.com/semgrep/semgrep-rules)
License: LGPL 2.1        Licensor: Semgrep, Inc.
```

It is the same semgrep-rules corpus under the same restriction. The *engine* is
genuinely LGPL-2.1 and unencumbered; the *rules* carry a Commons Clause forbidding
sale of a product or service whose value derives substantially from them.

**Opengrep over Semgrep CE therefore rests on governance, not licensing.** The engines
are comparable and rule-format-compatible. Opengrep is consortium-governed with no
paid tier above it, which is the safer dependency for a project that does not want its
default scanner's roadmap set by a vendor selling a competing product. The rule
licensing is identical either way, so it is not a differentiator and must not be cited
as one. Semgrep CE remains a configurable alternative for operators who prefer it.

**Consequences for an MIT project.** Distributing the rules inside the engine image is
permitted and unaffected. Selling a hosted `cavet` whose value derives substantially
from those rules is not. This is stated in the README and in the image's licence
notice rather than left for a downstream user to discover. An operator who needs a
wholly permissive stack can disable Opengrep in `config.yaml` and keep the fast tier,
which is entirely MIT and Apache-2.0.

Scanners are invoked directly inside the image. No intermediate orchestration layer —
the image provides the tool isolation that `awslabs/automated-security-helper` would
otherwise have supplied, so ASH is not adopted.

### 7.2.1 Image build

**Everything is baked in at build time.** No runtime installation, no entrypoint that
fetches scanners on first load, no cache volume. The digest determines the contents
completely — that is the whole basis of §3.4, and any runtime fetch would demote
repeatability from a property of the image to a property of a script holding its
version pins, with per-artefact checksums needed to make it stick. That is a lockfile
reimplementing what the image already provides.

It also keeps the default path fully offline (§7.5), which a first-run download step
would break — a proxied environment hanging on scanner downloads is precisely the
"conclude the tool is broken" failure this design avoids.

The image is not small, and that is accepted. Measured on a first build with
everything baked in, it was **4.49GB**:

| Layer | Size |
|---|---|
| Trivy java-db | 1.5GB |
| Trivy vulnerability db | 1.3GB |
| Trivy binary | 168MB |
| Opengrep binary | 104MB |
| Base OS + system deps | ~120MB |
| Gitleaks binary | 22MB |
| Opengrep rules (curated) | 20MB |

**The java-db is excluded by default.** It is 1.5GB — a third of the image — and is
only consulted when scanning JAR or WAR files that lack a resolvable `pom.xml`. That
is a narrow case to charge every operator 1.5GB for. Excluding it brings the image to
roughly 3.0GB. Operators scanning built Java artefacts enable it in `config.yaml`,
which selects the `full` variant tag.

The pull happens once and Docker caches it. To keep incremental cost low, **layers are
ordered by change frequency**:

1. Base OS and system dependencies — changes rarely.
2. Scanner binaries — changes on version bumps.
3. Rule sets and policy bundles — changes most often, and is the larger share.
4. Bundled vulnerability data.

A rules refresh therefore re-pulls a small top layer rather than the whole image.
Multi-stage builds drop build toolchains from the final image. `core` and `full`
variant tags carry the java-db distinction above — each still a single digest.

**Build-time requirements discovered by measurement.** Each of these is a hard
requirement, not a refinement; the image does not work without them.

- **A UTF-8 locale must be set.** Opengrep aborts with
  `UnicodeDecodeError: 'ascii' codec can't decode byte 0xc2` while reading its own
  rule files unless `LANG` and `LC_ALL` specify one. The failure surfaces as a Python
  traceback from inside the packaged binary and is thoroughly confusing cold.
- **The rule bundle must be curated at build time.** Pointing `--config` at a clone of
  `opengrep-rules` fails outright: the repository ships its own
  `.pre-commit-config.yaml` and `*.test.yaml` fixtures, Opengrep parses them as rule
  definitions, and the scan aborts with `invalid configuration file found`. The build
  copies the language directories only and strips test fixtures — 2031 YAML files
  reduce to 1818. This is mechanical filtering, not rule selection.
- **Trivy's misconfiguration policy bundle should be baked.** Without it Trivy logs
  `failed to check cache: cache does not exist at "/opt/trivy-cache/policy/content"`
  and falls back to embedded checks. Findings were unaffected in measurement, but the
  fallback is a network-dependent code path on a supposedly offline image.
- **Multi-architecture is a build-matrix concern only.** All three scanners publish
  prebuilt linux `x86_64` and `arm64` binaries, so §7's claim that architecture
  support is not a per-tool porting problem holds.

### 7.3 Git in the container

The repository is mounted **including `.git`**, and `git` is installed in the image.

- **Read operations** — `log`, `diff`, `show`, `blame` — need no credentials. Gitleaks
  needs history; diff-scoping needs `git diff`. Sandboxed read execution comes free.
- **Commits** need identity (`user.name`, `user.email`), not secrets. Supported.
- **Push, pull, fetch are out of scope.** The value is low — the operator pushes, not
  the agent — and it would put a live credential inside a container running
  third-party scanner code against untrusted repository content.

The entrypoint must run `git config --global --add safe.directory /workspace`, or git
refuses to operate on a mount owned by a different UID. Cheap to do, confusing to
diagnose cold.

### 7.4 Host integration

Handled programmatically by the CLI; no agent involvement:

- **Path translation.** Container paths (`/workspace/api/users.py`) are rewritten to
  host paths in both directions, including `C:\repo` ↔ `/workspace` on Windows.
- **File ownership.** `--user` is passed on Linux so files written to `.cavet/` are
  owned by the invoking user, not root. Not an issue on Docker Desktop, easy to miss
  until someone runs it on Linux.

### 7.5 Offline and proxied environments

Vulnerability databases want to phone home. A first run behind a corporate proxy
hanging for ninety seconds is how people conclude the tool is broken.

**Baking the database in is not sufficient — Trivy must be told not to update it.**
With networking disabled and default flags, Trivy does not fall back to the baked
database. It fails outright:

```
FATAL run error: init error: DB error: failed to download vulnerability DB
```

Trivy is invoked with **`--skip-db-update --skip-check-update --offline-scan`**, which
are mandatory. So invoked, the same scan completes offline in 1.8s and reports all 39
findings from the measurement fixture.

**The first reason for these flags is determinism, not offline support.** §3.4 rests
on the engine digest pinning one exact set of scanner binaries, rule sets *and
vulnerability data*. A Trivy that silently refreshes its database at runtime breaks
that guarantee without any visible symptom: the digest is unchanged, the delta is not
reproducible, and nothing in the output says so. The flags are what make the digest
mean what §3.4 claims it means.

Consequently the vulnerability data is refreshed by **rebuilding and re-digesting the
image**, which is a reviewable change to `engine/digest.txt`, and never by a scanner
updating itself mid-scan. Data staleness is bounded by image release cadence and is
visible; `cavet engine status` reports the baked database's build date.

- Vulnerability data is baked into the image where the tool supports it, so the
  default path needs no network at all.
- Gitleaks and Opengrep were verified to run correctly with networking disabled and
  need no equivalent flags.
- Proxy configuration and offline database paths are first-class `config.yaml`
  options, passed through to the container.

### 7.6 Graceful degradation

Missing capability → report it in `cavet engine status`, skip it, note the gap in scan
output. Never hard-fail.

Container **image** scanning requires mounting the Docker socket into the engine,
which is a meaningful privilege escalation. Off by default, opt-in per repository,
documented honestly. Filesystem and configuration scanning need no such access and
stay on.

If the Docker daemon is unreachable, `cavet` says so plainly and exits 2. There is no
degraded host-scanner fallback — that would reintroduce exactly the version drift the
image exists to prevent.

---

## 8. Subagent contract

Security work runs in an isolated context so that scanner volume and triage churn
never enter the main session. The parent receives only the final message.

**Input:** scope (`staged` | `diff <ref>` | `full` | `path`), phase, and any parent
context relevant to reconciliation.

**Output — structured, verbatim, never narrated:** the CLI's markdown table passed
through unchanged, plus the aggregate line and next-step hints, plus any verification
hints the subagent raises (§8.1).

The subagent's job is **triage and deduplication**, not narration. Full detail stays
on disk, addressable by id.

**Tool allowlist:**

- Read.
- Shell, scoped to the `cavet` binary.

**No Write.** Every artefact the subagent produces — a triage verdict, a raised
verification hint — is written by a `cavet` command, never by the agent's file tools.
A Write permission on `.cavet/`, however narrow, would let an agent bypass the
`events` package and hand-append JSONL that nothing validated. The binary is the only
author of the log, and the allowlist should say so.

An over-permissioned security subagent is worse than none.

**External evidence reaches the subagent through `cavet lookup` (§5.3), not through
its own web tooling.** The subagent does not need — and by default does not get —
search or fetch capability. Routing lookups through the CLI makes the constraints
structural rather than instructional: queries can only be built from identifiers,
sources are allowlisted in code, results are cached, and every lookup is attributable.

**Cite or omit.** Any triage verdict influenced by a lookup records the identifier and
canonical URL in the `triaged` event. An uncited lookup did not happen, as far as the
audit trail is concerned. This gives lookups the same reviewability §3.2 gives
findings — the operator can reconstruct not just what was dismissed, but what evidence
the dismissal rested on.

### 8.1 Verification hints

The subagent has no web access, and for the overwhelming majority of findings it needs
none:

| Finding type | External database? | What triage actually requires |
|---|---|---|
| **SCA / dependencies** | Yes — CVE, GHSA, OSV | `cavet lookup`: affected range, fixed version, exploited status |
| **SAST** | **No — an Opengrep match is not a CVE** | Reading the code: reachability, whether the input is untrusted, whether it is a test fixture. Rule metadata ships in the engine image |
| **Secrets** | No | Reading the code, entropy, optional live verification by the scanner |
| **IaC** | No | Rule guideline plus stable, well-represented provider semantics |

This is why the absence of web access is correct rather than a limitation: three of
the four categories have **nothing to search**, and the fourth has a structured API.

What remains is the occasional finding whose resolution turns on something neither the
code nor an advisory answers — usually a **remediation** question rather than a triage
one. That belongs to the parent, which holds the operator context, the conversation
history, and whatever tooling the operator has chosen to provide.

So the subagent does not stall and does not guess. It **emits a verification hint** and
lets the parent decide.

**Form.** Structured, alongside the findings table, never prose:

```
verify[1]{id,question}:
  a3f9c2,does this framework's response middleware support masking a named field in
         the serialised payload, or must it be stripped before serialisation?
```

Distinct from the CLI's `next:` hints (§4), which are commands to run. A verification
hint is a **question for the parent**, not an instruction — the parent may answer it
from its own knowledge, look it up, ask the operator, or judge it not worth pursuing.

**Recorded.** The subagent runs `cavet raise --kind verification` with the question
and the fingerprint of the finding it concerns, producing a `raised` event. The parent
closes it with `cavet resolve`, producing a `resolved` event carrying the answer and
any sources. This is the same lifecycle
design-phase concerns use, which is why both appear in `cavet items` — and it is why
no tenth event type is needed.

**Disposition.** A finding awaiting verification is triaged `confirmed` with
`confidence: low` and surfaced normally. Uncertainty is visible to the operator rather
than resolved by guesswork.

**Constraint.** Hints carry the *question*, not repository content. The parent may
legitimately search with more context than the subagent could — it operates under the
operator's direct observation, using tooling the operator installed, which is a
materially different risk posture to an isolated subagent making unattended queries.
That difference is the reason the hint mechanism is acceptable where subagent web
access was not.

---

## 9. Triggers

Optional, operator-installed, **off by default, advisory only**.

A git `pre-commit` hook that runs `cavet scan --staged`. It does not invoke a model — a
git hook is a subprocess with no channel into a running agent session. It runs the
deterministic scan, prints the compact result, and **exits 0 regardless** unless the
operator configures otherwise.

`--staged` is the fast tier (§5.2): Gitleaks and Trivy, ~1.8s warm. A hook is the one
place where latency is not negotiable — it sits between the operator and every commit
they make — and 1.8s is comfortably below the threshold at which people start passing
`--no-verify` out of habit. SAST is deliberately absent here; catching a secret or a
vulnerable dependency at commit time is worth 1.8s, and catching a SAST finding is not
worth 50.

The mechanism that makes this useful: when the agent runs `git commit` through its own
shell tool, the hook's output lands in the agent's context automatically. No IPC, no
harness coupling. The agent sees the findings whether or not it thought to look.

Installed by `cavet init --hooks` via `core.hooksPath` so it survives a fresh clone. On
Windows it must run under Git for Windows' bash or shell directly to the binary —
verify on day one.

A convenience trigger, one among several. Not the spine of the product.

---

## 10. Implementation

### 10.1 Language and distribution

**Go.** The CLI is a thin orchestrator: spawn container operations, parse JSON, render
markdown, append JSONL, translate paths. Nothing performance-sensitive — the scanners
dominate wall time.

Go is chosen for three specific reasons: the official Docker SDK is first-class, which
matters because container lifecycle management is central to the architecture;
cross-compilation to Windows, macOS, and Linux on amd64 and arm64 is trivial with no
per-target toolchain; and the surrounding ecosystem (Trivy, Gitleaks, Opengrep's tooling) is
Go, so contributors already read it.

Distribution: a single static binary per platform via GitHub Releases, plus whatever
package managers are cheap to add later. No runtime for the operator to install.

### 10.2 Type discipline

Go's weakness for this program is the data model — nine event types, a verdict enum,
severity levels, and a scan-scope union, none of which the compiler will check
exhaustively.

Mitigation: a single `events` package owning every constructor and constant. No raw
string literals for event types, verdicts, severities, or phases outside it. Schema
version recorded on every event so the log stays readable as the model evolves.

---

## 11. Skills

**Hard cap: six top-level skills.** Adding a seventh requires deleting one. Focused
skills outperform exhaustive bundles, and the natural drift is one skill per phase ×
stack × framework, which is context bloat through a different door.

Depth lives in `references/` beneath each skill, loaded on demand.

**Every skill is prefixed `cavet-`.** Because Agent Plugins 1.0 is not used (§2.2),
installers place skills as loose directories under each harness's skills path, in a
flat namespace shared with the operator's own skills and any third-party ones. An
unprefixed `design-review` or `triage` would collide. The prefix also makes
attribution obvious when something misfires, and makes uninstalling a matter of
deleting anything matching a glob.

The prefix carries the security signal, so the names do not repeat it —
`cavet-design`, not `cavet-security-design`.

| Skill | Phase | Fires on |
|---|---|---|
| `cavet-design` | Design | Architecture, feature, integration, data-flow, auth, or third-party-service discussion |
| `cavet-design-review` | Design → Build | A design being finalised |
| `cavet-triage` | Build, Test | Code written or changed; scan results needing interpretation |
| `cavet-secure-coding` | Build | Any code being written or modified |
| `cavet-supply-chain` | Build, Deploy | Adding or updating dependencies |
| `cavet-deployment` | Deploy | IaC, secrets management, runtime configuration |

### 11.1 `cavet-design` — the differentiating component

Everything else in this project has competitors. This does not.

The requirement: when the operator is brainstorming a feature — say, adding
bring-your-own-key LLM integration to a documentation tool — the agent considers not
just how to build it but how to build it **securely**, without being asked.

**Triggering.** The skill description must fire on *design activity*, not on security
vocabulary. "Brainstorming BYOK integration" does not match a skill called
`threat-modeling`. The description must cover architecture, new features,
integrations, data flows, authentication, and third-party services in general terms.

**Reinforcement.** Skill matching is probabilistic. Three to five lines in the
project's agent instruction file establishing that design discussions surface security
implications alongside functional ones. This is the *only* place in the project where
resident tokens are spent, and it is worth it — it is the one mechanism that fires
reliably when nobody asked.

**Behaviour.**

- Fire at **decision points with security consequence**. "Where do the keys live" —
  yes. "What should we call the config file" — no. Getting this wrong in either
  direction is fatal: too eager and the operator disables it; too shy and it is not
  there when it matters. The skill needs explicit negative examples.
- Default output: the flag plus **one line of consequence**. No lecturing, no
  narrative.
- Full rationale — threat, likelihood, what breaks — only when asked ("why encrypt
  keys server-side?", "why does encryption matter on an intranet-only deployment?").
  That depth lives in `references/`, not inline.
- **Never re-raise an item already open.** The open-items list is what makes "do not
  nag" structural rather than aspirational.

**Trace.** When a concern is raised and the conversation moves on, the skill runs
`cavet raise --kind design` and it becomes a `raised` event and an open item. Deferring is a legitimate outcome, recorded as such.

### 11.2 `cavet-design-review` — the checkpoint

A full sweep when a design is finalised, because conversational mode is probabilistic
and things get deprioritised mid-flow.

Critically, the checkpoint **does not re-derive from the design document alone**. It
reads the open-items list, so it catches the class of thing that was raised, correctly
deprioritised at the time, and then forgotten.

Two tiers of output, first tier ranked higher:

1. **Raised and unresolved** — you saw this, you passed, here it is again with your
   stated reason.
2. **Never raised** — gaps found by sweeping the finalised design against a checklist.

Output: updates to `design/threat-model.md` and `design/decisions/`, which carry the
reasoning forward so build-phase findings are interpretable in context.

### 11.3 `cavet-secure-coding` — preventive, in the parent thread

Fires on **any code being written or modified**. The trigger is deliberately
unqualified: any narrower condition would require the agent to first recognise that a
piece of code touches security, and that recognition *is* the knowledge this skill
carries. A skill gated on its own contents fires only when it is least needed.

**Runs in the parent thread. No subagent.** Scan triage is isolated because it is
review-time work with high-volume output and little residual value. This is
generation-time work: the patterns must be present while the code is being written,
in the same context as the code. A finding prevented at write time is a finding that
never has to be detected, triaged, surfaced, or fixed.

**Shape: a contrast table, not prose.** The skill's job is to let the agent tell the
insecure construct from the secure one at the moment of writing:

| Insecure | Secure | Why |
|---|---|---|
| Username concatenated into a SQL string | Parameterised query, username validated against an expected shape | Separates data from statement; concatenation cannot be made safe by escaping alone |
| Shell command assembled by string interpolation | Argument vector, no shell | Removes the shell's parsing stage entirely |
| MD5 or SHA-1 for token derivation | CSPRNG for generation, constant-time comparison | Fast hashes are the wrong primitive; comparison timing leaks |
| Redirect target taken from request | Allowlist of permitted destinations | Open redirect is a phishing and token-leak primitive |
| Credential in source or config committed to VCS | Injected at runtime from the platform's secret store | Version control has no forgetting |

Illustrative, not the full set. The shipped table is the general cross-language core.

**Depth in `references/`,** organised per language and framework, loaded only when the
agent is working in that stack. This matters more here than in any other skill: a
trigger this broad means the skill body loads often, so the body must stay thin and
the specifics must live one level down.

**Relationship to the scanners.** This is preventive; SAST is detective. The overlap
is deliberate and the redundancy is the point — the pattern that gets applied at write
time and the rule that would have caught it are two independent chances at the same
outcome.

### 11.4 Installers

First-party installers for a small set of harnesses — Claude Code, Codex, OpenCode,
Pi, Hermes — covering skill placement, subagent definitions, and tool allowlists.

Everything beyond that is the operator's to wire up, against `cavet describe --json`.
Harness-install support, doctors, and verification tooling are explicitly **not** core
scope: harness extension surfaces change constantly and maintaining them would consume
the project.

---

## 12. Lifecycle

| Phase | Skills | Deterministic tools | Artefacts written |
|---|---|---|---|
| **Design** | `cavet-design` (conversational), `cavet-design-review` (checkpoint) | — | `design/threat-model.md`, `design/decisions/`, `raised`/`resolved` events |
| **Build** | `cavet-triage`, `cavet-secure-coding`, `cavet-supply-chain` | Fast tier: secrets, SCA, IaC | findings events, `reports/` |
| **Test** | `cavet-triage` | Deep tier: full-tree SAST, secrets, SCA | findings events |
| **Deploy** | `cavet-deployment` | IaC, container, secrets | findings events, `reports/` |

Every phase writes to the same log and the same state files. Design items and code
findings share a lifecycle — raised → deferred / dismissed / resolved, with rationale —
which is what makes the two halves one product rather than two.

---

## 13. On record

### 13.1 Name availability — checked 2026-08-17

| Registry | `cavet` | Note |
|---|---|---|
| npm | **Free** | 404 on `registry.npmjs.org/cavet` |
| PyPI | **Free** | 404 |
| crates.io | **Free** | Crate does not exist |
| Homebrew | **Free** | No formula; tap-distributable regardless |
| GitHub username/org | **Taken** | `github.com/cavet` is an existing user account |
| GitHub repo name | Free in practice | Three unrelated `Cavet` repos exist, all zero-star (a Catalan coastal campaign, a band site, a stub). Repo names are per-owner, so no conflict |

The package name is clear everywhere it matters and the binary name is unaffected. Only
the GitHub *organisation* is unavailable — publish under a different org or a personal
account with the repository named `cavet`, which is what install and documentation URLs
will reference anyway. No trademark conflicts surfaced.

**Settled 2026-08-25:** the repository lives at `github.com/ChaosChild/cavet` (personal
account, private until v0.1 stabilises); the module path is `github.com/ChaosChild/cavet`
and the engine image `ghcr.io/chaoschild/cavet-engine`.

### 13.2 Deferred: evaluation fixtures

A set of small repositories with planted vulnerabilities of known classes, run across
multiple harnesses and models with and without `cavet`, measuring detection rate,
tokens, and turns against a no-tool baseline.

Deliberately deferred until after real-world use. In the meantime, keep a running log of
every miss and false positive encountered in practice — that log *is* the fixture set
later, and it costs nothing to keep now.
