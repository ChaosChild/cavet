# Backlog

Deliberately tracked, deliberately unscheduled: items land here when the cost
of forgetting them exceeds the cost of writing them down, and move to Closed
when they ship. Ordering is the maintainer's call.

When an item ships, move it below the line with the completion date and the
version that carried it. Last updated: 2026-09-10.

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
first-class citizens of the audit trail.

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

### `cavet serve` dashboard

A local, human-readable web dashboard over cavet data: findings, triage state,
remediation and velocity. Launched with `cavet serve` on an open port;
read-only first, no UI-driven mutations. Design questions when picked up:
localhost-only bind vs LAN, live event log vs snapshot, and what velocity
metrics need captured at event time.

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
