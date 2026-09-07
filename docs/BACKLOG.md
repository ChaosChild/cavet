# Backlog

Deliberately tracked, deliberately unscheduled: items land here when the cost
of forgetting them exceeds the cost of writing them down, and move to Closed
when they ship. Ordering is the maintainer's call.

When an item ships, move it below the line with the completion date and the
version that carried it. Last updated: 2026-09-07.

## Open

### `cavet import`

cavet's event model cannot ingest external scanner output: findings from
non-workspace scans live in report files while only the decisions get recorded
(via `cavet raise` / `cavet resolve`). An import path would turn external
findings into detected events with a distinct provenance and make them
first-class citizens of the audit trail.

### Native Docker image scanning

When a project has a Dockerfile, `cavet scan` should build and scan the image
and report image vulnerabilities like any other finding (detected event ->
triage -> remediation or debt). The engine already bundles Trivy, so the work
is scan-pipeline scope, config gating and findings plumbing. This generalizes
the weekly posture cron and `cavet import` for the engine-image use case, and
would retire the manual scan-local flow. Design questions when picked up:
build from the Dockerfile only, or also referenced and composed images; tier
placement (image builds are slow, own tier or part of `--full`); fingerprint
and baseline semantics for artifacts (key by Dockerfile plus base-image
digests, not source lines).

### Digest-pin the golang build stage

The engine's source builds (gitleaks, trivy) float the minor tag of
`golang:1.26-bookworm` so rebuilds pick up Go patches. Pinning the stage by
digest would freeze the supply chain at the cost of manual toolchain bumps.
Decide at the next supply-chain posture review.

### `cavet serve` dashboard

A local, human-readable web dashboard over cavet data: findings, triage state,
remediation and velocity. Launched with `cavet serve` on an open port;
read-only first, no UI-driven mutations. Design questions when picked up:
localhost-only bind vs LAN, live event log vs snapshot, and what velocity
metrics need captured at event time.

## Closed

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
