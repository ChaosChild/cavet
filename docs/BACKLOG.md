# Backlog

Deliberately tracked, deliberately unscheduled: items land here when the cost
of forgetting them exceeds the cost of writing them down, and move to Closed
when they ship. Ordering is the maintainer's call. Near-term items are small,
concrete and evidence-backed, ready to pick up without a design round; the
Open list is a roadmap, not a sprint plan, and its items may name horizons and
prerequisites that do not exist yet, anchored on another product's own roadmap
(the golang 1.27 item is the pattern: revisit when trivy ships past 0.74.0).
Where an item touches cavet's determinism claim, it says so:
engine-deliverable, boundary-ingested, or host-measured.

When an item ships, move it below the line with the completion date and the
version that carried it. Last updated: 2026-09-17.

## Near-term

### Include dev dependencies in workspace scans (critical path)

Root cause of the 2026-09-17 nanoid miss (GHSA-2v37-7h3g-55p8 /
CVE-2026-67213, reproduced against the shipped engine bytes): the shipped
trivy DB knows the advisory, but cavet's trivy invocation never passes
--include-dev-deps, so every `dev: true` package in every lockfile is
silently skipped, and the vulnerability sat in a dev chain (vite,
postcss, nanoid). Fix shape: a `scanners.dev-deps` config knob, default
on, passing --include-dev-deps, with dev-chain findings carrying a
visible context marker in scan output and serve. Whatever the knob
ends up being, scan output declares what was excluded. Expect a
one-time baseline step-up on JS-heavy repos and fold the rollout note
into the next instruction-layer pass. CLI-only: no engine rebuild
needed.

### `cavet doctor` (state-vs-log consistency check)

Replay the log and diff the result against `state/` without writing:
report drift, never repair. Evidence from the 2026-09-07 v0.1.1 session:
five triage verdicts and open item it-e7b70a3f went missing from on-disk
state while the log stayed intact; no code path on HEAD wipes verdicts,
and the drift survived nine days until a triage pass tripped over it. A
same-day check would have caught it. State is derived, the log is truth,
but nothing verifies that today.

### Rebuild should re-mark in_baseline

Verified on HEAD: store Rebuild() (internal/store/rebuild.go) preserves
baseline.json via loadBaseline but never sets f.InBaseline on replayed
findings, so after the 2026-09-16 rebuild all 663 rows carry
in_baseline: false. `cavet debt` is unaffected (it reads
Baseline.Fingerprints directly), but any display reading the flag can
mislabel until the next rebaseline. Fix shape: after loadBaseline, mark
findings with Verdict == nil whose fingerprint is in
Baseline.Fingerprints.

### `cavet log` row cap

The log view hard-caps at 50 rows (internal/cli/logdebt.go) with no flag
to raise it; the 2026-09-16 forensics had to read
.cavet/log/events-2026-09.jsonl directly (3,121 events). Fix shape: a
--limit flag, default 50.

### `cavet debt` should reflect triage verdicts

`cavet debt` lists every baseline fingerprint, including rows that
already carry dismiss verdicts (66+ as of 2026-09-16), so working the
queue means re-reading known-dismissed rows. Fix shape: hide triaged
rows by default or add a verdict column, leaving only what is actually
undecided.

## Open

### golang 1.27 for the engine source builds

Dependabot's 1.27-bookworm bump (PR #25) is closed and its 1.27.x minor
ignored: trivy v0.74.0 does not compile on Go 1.27 because the revised
encoding/json/v2 experiment dropped json.SkipFunc, and the engine builds
trivy with GOEXPERIMENT=jsonv2 to mirror the upstream release build.
Revisit when trivy ships past 0.74.0; also check whether that release
carries grpc 1.83.1 or newer, which would let the engine flip back to
release tarballs instead of source builds.

### `cavet import`

cavet's event model cannot ingest external scanner output: findings from
non-workspace scans live in report files while only the decisions get recorded
(via `cavet raise` / `cavet resolve`). An import path would turn external
findings into detected events with a distinct provenance and make them
first-class citizens of the audit trail. Likely first consumers:
language-native linter output for languages no sub-engine covers (the
engine corpus has no Rust at all, and clippy found what Opengrep could
not) and host-side test-coverage results feeding the quality indicators
item. Determinism boundary, stated honestly: import is
optional and prose-fed by nature and can never carry the engine's fixed-
deliverable guarantee over content. What it must carry is process
determinism: same report plus same importer version yields the same events,
the source artifact is hashed into the log, and provenance marks every
imported event as external. That replaces "trust me, I ran something" with an
auditable record, which serves cavet's goal at the boundary instead of inside
the engine.

### Dockerfile auto-discovery for image scanning

Image scanning config covers repo-root Dockerfiles under `true` or an
explicit list of paths, nested ones included. Discovery beyond that
(config-driven globs or recursive search with sensible exclusions) removes
the need to maintain the list by hand as images are added to a repository.

### Image staleness tracking

A base image can move under an unchanged Dockerfile (`:latest` tags) and
installed dependencies drift with it. Record resolved base-image digests and
installed dependency versions at image-scan time; surface drift since the
last image scan so operators know when to re-run `cavet scan --image`
without a Dockerfile change.

### A non-security verdict for triage

`dismissed` means "not worth acting on" and hides the finding from every
surface afterwards: the exact opposite of what real-but-not-security
findings need. Bugs, slop and lazy coding surfaced during triage should
leave the security gate yet stay visible to agent and operator as
backlog material. Adds a third verdict `not-security` alongside
confirmed/dismissed with its own visibility rules in scan output, serve
and metrics, plus the instruction layer: the triage skill, agent
definitions and installers teach the verdict vocabulary, and a verdict
agents never learn is a verdict never used (PR #41 in miniature).
Unblocks the quality scanner item below.

### Rework the `deferred` status

Deferred and dismissed are behaviorally identical today: neither is
actionable, and deferred is not even counted in scan output, so a
deferral is indistinguishable from a rejection with a politer name.
Rework, decided in the 2026-09 backlog round: deferred gets visibility
of its own (count and listing) and an explicit horizon, an until-date
recorded at defer time, with overdue deferrals surfaced as a derived
read-time view, never synthetic events, so agents and operators re-triage
them instead of forgetting them. State never flips itself: re-triage of
an overdue deferral stays an actor's decision.

### Quality indicators: coverage, hotspots, metrics

Open, discussed 2026-09-16: three signal classes belong beside the hard
findings without being CVE-shaped. Test coverage does not prove a
deficiency is tested, it measures the odds, and its agent value is the
join, findings located in untested code; it is produced host-side by the
project's own toolchain, so it rides `cavet import`, not the engine.
Taint and security hotspots, arguably the most important class, partly
exist already in the corpus's taint and audit rules; the gap to
SonarQube is depth, not existence, and the hotspot workflow is triage by
another name. Duplication and complexity are spot-check indicators with
a security half-life (divergent fixes of duplicated code, mispatches of
complex code); rule engines cannot express them, so they imply small
dedicated tools, which unlike coverage can run inside the engine
container. Working proposal: indicators enter the log as items, not
findings, reusing raise/resolve, the path design and verification items
already take: measurement-shaped and review-shaped concerns, never
gating, visible to agent and operator, exportable once `cavet export`
lands. Findings stay defect-shaped; the corpus's quality-class rules
keep flowing through findings plus the `not-security` verdict. Field
context: the corpus has no Rust at all and clippy found what Opengrep
could not; the roadmap answer is the language sub-engines item below,
with `cavet import` covering whatever no sub-engine does. SonarQube
remains the depth
benchmark for deep taint and coverage-as-product. Prerequisites when
this moves: the lifecycle vocabulary workstream for the items lane, and
`cavet import` for coverage; complexity and duplication tools can land
without either, and a six-month-shaped dependency is fine on a roadmap.

### Engine extensibility: language sub-engines

The core engine covers exactly the languages its corpus covers (24 rule
directories, no Rust), and the fallback for everything else is prose:
trust the coding agent, which cavet does not control, to run the native
linter and import the output. The roadmap answer is to extend the engine
family instead: language-specific sub-engines, rust plus clippy as the
first candidate, built and pinned with the same discipline as the core
image (digests, offline, curated toolchain) and emitting the same event
shapes into the same log. The point is not the toolchain, it is the
log: cavet's product surface is prose in agent skills, but the record
is what lets an operator or a later agent ask "why did you dismiss
this?" and get an answer from the log rather than the agent's memory.
Import remains the home for what no sub-engine covers; both paths share
the provenance rules stated under `cavet import`. Classification:
engine-deliverable.

### Advisory freshness for workspace scans

The engine bakes the trivy DB at build time (engine/Dockerfile:125) and
retags preserve bytes, so workspace scans are blind to advisories
published after the last real build: the shipped DB dates 2026-09-07
and ages without bound. The 2026-09-17 nanoid incident was not this
(it was the dev-dependency item above), but this gap produces its own
incident on the first post-build advisory. The weekly posture cron
already pairs fresh advisory data with pinned engine bytes for the
engine image itself (trivy-action in image-posture.yml); workspaces
need the same. Decided direction: decouple the DB from the image
bytes. Trivy stays pinned in the image; the DB moves to a managed cache
volume, and an explicit operator command (`cavet engine update-db`)
pulls the trivy-db OCI artifact by digest, verifies it and swaps it.
Scans stay offline, and every scan records the DB digest it ran with:
determinism restated as recorded inputs, findings a function of engine
digest, DB digest and workspace. Rejected: scheduled full rebuilds
(digest churn breaks baselines); a fresh-scan sidecar via `cavet
import` remains the fallback, and ecosystem-native importers (npm
audit, pip-audit, cargo audit) ride `cavet import` as a complement.
DB-age awareness ships with it: `cavet version` reports the engine ref
and DB age, scan output and `cavet doctor` surface staleness, and the
skills nudge the agent to check age and alert the operator before
scanning with a stale DB (days old: proceed; months old: suggest
`cavet engine update-db` first). Operators cannot be expected to know
the DB needs updating; a critical missed by cavet while npm audit
catches it is a reputation failure the product can prevent.
Classification: engine-deliverable; the update command is an explicit,
digest-verified operator action at the boundary.

### Task management awareness for findings

An agent querying cavet cannot tell a finding is planned, assigned or in
progress elsewhere: leaving it open re-raises it every scan, dismissing
it hides it and records a verdict that is not true. Phased delivery,
decisions folded in from the 2026-09 backlog round: a `worked-elsewhere`
status (new event kind, own visibility) whose payload is a plain-text
reference in the reason, nothing structured ("worked on in TICKET-123"),
since cavet points at the tracker without mirroring it; rescans resolve
worked-elsewhere findings by absence exactly like every other finding.
Then `cavet export`, first cut markdown for a single finding, ready to
paste into Jira, Linear or a GitHub issue with the cavet display ID
carried along. Round-trip sync is a definitive non-goal: tracker APIs
stay out of cavet, and the parent coding agent manages trackers through
its own MCPs and CLIs.

## Closed

### `cavet serve` dashboard (2026-09-15, v0.2.1)

Shipped loopback-only (the dashboard has no auth, so cavet never listens
beyond `127.0.0.1`), read-only, load-on-open plus manual refresh. Carries a
severity posture strip, inline-SVG trend charts with hover read-outs over the
precomputed metrics cache, server-side filtered findings with per-finding
detail and event history, and open items.

### Native Docker image scanning (2026-09-10, v0.2.0)

`cavet scan --image` builds configured images host-side via `docker buildx`
and scans them inside the offline engine with Trivy: `scan.container_images`
is bool or list (with optional per-entry `target:`), managed by
`cavet image add/remove/list`; image scans also fire automatically in `--full`
and in `--staged` when a configured Dockerfile is staged. Findings carry
package-identity fingerprints in the `img:` namespace, locate at their
Dockerfile, and only an image scan can remediate them by absence. Dogfooded on
this repository's own engine image (`engine/Dockerfile`, target `final-core`,
565 findings folded into the baseline), which retired the manual
`engine/scan-local.ps1` flow. Decision trail: PR #31.

### Digest-pin the golang build stage (2026-09-08, unreleased)

Both golang source-build stages (gitleaks, trivy) pin the 1.26-bookworm
manifest-list digest, so scanner-binary builds are reproducible and
Dependabot's weekly docker updates bump the digest instead of drifting the
tag. The debian:bookworm-slim base stays tag-pinned on purpose: that stage
takes apt security updates at build time.

### Engine digest rebaseline (2026-09-07, v0.1.1)

This repository adopted the v0.1.1 core engine digest (`cavet engine pull`,
then `cavet rebaseline`: 71 findings re-recorded, verdicts preserved) and
resolved the accepted-risk item recorded during the CVE-2026-84304 grace
window.

### `cavet update` (2026-09-07, v0.1.1)

In-place self-update: resolves the latest GitHub release, verifies it exactly
like the installers (checksums.txt, plus the Sigstore bundle when cosign is
installed) and swaps the running binary at its real install location, wherever
that is. `--check` reports only; up-to-date and development builds short-
circuit with guidance. Exists because re-running an installer defaults to
`~/.local/bin` and can shadow the real install (Homebrew, Scoop, `go install`,
manual).

### Trivy grpc fix in the engine image (2026-09-07, v0.1.1)

CVE-2026-84304 (HIGH) is grpc-go 1.82.1 embedded in trivy 0.74.0, which was
still the latest upstream release, so no version bump could fix it. The engine
now source-builds trivy from its pinned tag with grpc bumped past the upstream
pin, the same pattern as the gitleaks source build (pinned tag plus go
module-hash provenance instead of a tarball sha256). Both variants scan
0 CRITICAL / 0 HIGH.

### Pre-commit hook in linked worktrees (2026-09-01, v0.1.0)

`cavet scan --staged` from a linked git worktree misresolved the gitdir and
exited 2. Fixed with proper GIT_DIR / GIT_WORK_TREE handling, protected-config
env, a stale-gitfile guard and container auto-recreation.

### Weekly engine posture rescan (2026-09-01, v0.1.0)

Advisory drift can attach a new CRITICAL to identical image bytes after a
release. A weekly cron now scans the rolling engine tags CRITICAL-only, stays
silent when green, and opens exactly one tracked issue on findings.
