# cavet — Engine Specification

**Status:** Component annex to [`SPECIFICATION.md`](SPECIFICATION.md). Implementation-grade.
**Scope:** the `cavet-engine` OCI image — contents, build, variants, entrypoint
contract, acceptance criteria. Consumed by the CLI through the contracts of
[`cli-spec.md`](cli-spec.md) §7 and §10.
**Date:** 2026-08-21

Everything measurable here was measured: spike [`spike-2026-08-21-scanner-baseline.md`](spike-2026-08-21-scanner-baseline.md)
ran these exact tools and recorded the failure modes this build exists to prevent.

---

## 1. Identity

| Property | Value |
|---|---|
| Name | `ghcr.io/chaoschild/cavet-engine` |
| Variants | `core` (default), `full` — differ only in Trivy's java-db layer |
| Tags | `core`, `full`, plus `core-<digest8>` / `full-<digest8>` retags at publish |
| Architectures | linux/amd64, linux/arm64 (build matrix; all scanners ship prebuilt binaries for both — spike §6) |
| Base | `debian:bookworm-slim` |
| Size budget | ~3.0 GB core (measured 4.49 GB with java-db; excluding it ≈ 3.0 GB — spike §6) |

Plain OCI only — no Compose, no Docker-specific features; `podman` builds and runs it
unchanged (spec §7).

---

## 2. Contents

| Capability | Tool | Version pin | Licence |
|---|---|---|---|
| SAST | Opengrep | 1.27.1 (spike baseline) | LGPL-2.1 (engine); rules **LGPL-2.1 + Commons Clause** |
| Secrets | Gitleaks | 8.30.1 | MIT |
| SCA / IaC / secrets | Trivy | 0.74.0 | Apache-2.0 |
| IaC *(optional)* | Checkov | latest-pinned-at-build | Apache-2.0 |
| VCS | git | Debian bookworm package | GPL-2.0 |
| Locale | locales | system | enables `C.UTF-8` |

Checkov ships because removing it later is cheaper than adding it under pressure; it
is inert unless a scan invokes it (`config.scanners.checkov`).

### 2.1 Version pins

One build-args block in `engine/Dockerfile` is the only place versions appear:

```dockerfile
ARG OPENGREP_VERSION=1.27.1
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.74.0
ARG CHECKOV_VERSION=3.2.30
```

A version bump is one line + one digest change via `cavet rebaseline`. Nothing else in
the repo may hardcode a scanner version; CI greps for violations.

---

## 3. Dockerfile structure

Multi-stage. Stage order encodes spec §7.2.1's layer-frequency ordering — least
volatile first — so a rules refresh re-pulls only the top layers.

```dockerfile
# syntax=docker/dockerfile:1

FROM debian:bookworm-slim AS base
# locale, git, ca-certificates, uid/gid passthrough support
# LANG/LC_ALL=C.UTF-8 baked here (spike §6: Opengrep aborts without it)

FROM base AS scanners
ARG OPENGREP_VERSION …
# download & install pinned binaries into /usr/local/bin
# checksum-verified downloads (sha256 per release asset, checked in RUN)

FROM scanners AS rules
# clone opengrep-rules at pinned commit → curate → /opt/opengrep-rules
# see §4

FROM scanners AS trivy-data-core
# trivy image --download-db-only --cache-dir /opt/trivy-cache        (vuln db, 1.3GB)
# bake misconfig policy bundle → /opt/trivy-cache/policy  (§5)

FROM trivy-data-core AS trivy-data-full
# + --download-java-db-only                                          (java-db, 1.5GB)

FROM rules AS final-core
COPY --from=trivy-data-core /opt/trivy-cache /opt/trivy-cache
# entrypoint, healthcheck, LICENSES.md, env

FROM rules AS final-full
COPY --from=trivy-data-full /opt/trivy-cache /opt/trivy-cache
# identical otherwise
```

Rules sit *above* the data layers in volatility terms but below them physically is
wrong — the ordering that matters: base → binaries → rules → data. A rules bump then
invalidates only the data COPY layers' cache when their inputs changed, which they do
not. In practice: rules refresh re-downloads ~20 MB of curated rules; DB refresh
re-downloads the DB layer only. Both are visible as separate digests; both go through
`cavet rebaseline`.

### 3.1 Environment contract (baked)

```dockerfile
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV TRIVY_CACHE_DIR=/opt/trivy-cache
ENV OPENGREP_RULES=/opt/opengrep-rules
ENV GITLEAKS_CONFIG=/opt/gitleaks.toml
```

`TRIVY_CACHE_DIR` redirects every Trivy invocation to the baked cache without flags;
the CLI still passes the three offline flags explicitly (defence in depth,
cli-spec §7). `/opt/gitleaks.toml` is a stub allowing everything — present so a future
allowlist feature has a home, harmless now.

---

## 4. Rules curation stage

The opengrep-rules repository cannot be scanned as-is: its own CI config and test
fixtures parse as rule definitions and abort the run (spike §6). Curation is
**mechanical filtering, not rule selection** (spec §7.2.1) — the decision not to
curate a subset is recorded in the spike ("What this changed") and stands.

Build-stage algorithm:

1. Clone `opengrep-rules` at a **pinned commit SHA** (another ARG) — tag drift would
   silently change the rule corpus between rebuilds of the same version number.
2. Keep language directories only: every directory containing `*.yaml` rules by
   language convention (`python/`, `javascript/`, `go/`, `terraform/`, …).
3. Exclude, mechanically: `*.test.yaml`, `*.fixture.*`, `.pre-commit-config.yaml`,
   top-level non-language configs, hidden directories.
4. **Assert count**: expected file count range [1700, 2100] — measured 1818 after
   filtering from 2031 (spike §6). Outside the range → build fails loudly rather than
   shipping a silently-shrunken or exploded corpus. The range is wide on purpose: it
   catches structural breakage, not ordinary upstream churn.

---

## 5. Trivy policy bundle

Spike §4: unbaked, Trivy logs `failed to check cache: cache does not exist at
"/opt/trivy-cache/policy/content"` and falls back to embedded checks over a
network-dependent path — unacceptable on an offline-by-construction image even when
findings happen to match. The bundle is downloaded with the same pin discipline as
scanner versions (Trivy version determines the compatible bundle) and baked at
`/opt/trivy-cache/policy`. Acceptance test §8.2 asserts its presence.

---

## 6. Entrypoint and runtime contract

### 6.1 Entrypoint script (`/usr/local/bin/cavet-entrypoint.sh`)

```sh
#!/bin/sh
set -e
git config --global --add safe.directory /workspace
mkdir -p /reports /scan
exec "$@"
```

- `safe.directory` first — git refuses mounted-repo operations otherwise and the error
  is confusing cold (spec §7.3).
- `/scan/` scratch for checkout-index staging, `/reports/` for SARIF output — both
  created fresh; the container holds no unique state, so restarts are free.
- Default `CMD` absent: the CLI always names the process it wants (exec model,
  cli-spec §10.3).

### 6.2 Healthcheck target (`/usr/local/bin/cavet-healthcheck`)

```sh
#!/bin/sh
set -e
gitleaks version >/dev/null
trivy --version >/dev/null
opengrep --version >/dev/null
git --version >/dev/null
[ -d /opt/trivy-cache/policy/content ]
[ -d "$OPENGREP_RULES" ] && [ "$(find "$OPENGREP_RULES" -name '*.yaml' | head -1)" ]
```

Exit 0 = warm and complete. The CLI probes this before every scan (cli-spec §10.2);
it doubles as the image's Docker `HEALTHCHECK`.

### 6.3 Users and permissions

Runs as root inside the container by default; on Linux hosts the CLI passes
`--user $(uid):$(gid)` so any accidental workspace write stays user-owned (spec §7.4).
No sudo, no privileged mode, no capabilities beyond default. Container-image scanning
(the Docker-socket mount) is a CLI-side opt-in; the image neither requires nor cares.

---

## 7. Licence notice

`/LICENSES.md` baked into both variants, containing verbatim:

- Opengrep engine licence summary (LGPL-2.1) and where to find full text.
- The Commons Clause notice text from `opengrep-rules/LICENSE` **in full**, including
  "does not grant to you the right to Sell", attributed to Semgrep, Inc.'s
  semgrep-rules corpus (spike §1 quotes it precisely — copy that text, not a
  paraphrase).
- Gitleaks MIT, Trivy Apache-2.0, Checkov Apache-2.0 attributions.
- One line: *"Distribution inside this image is permitted. Selling a product or
  service whose value derives substantially from the rule corpus is not."*

Spec §7.2 requires this be stated in the image, not discovered downstream.

---

## 8. Acceptance criteria

CI runs against every image build. These are the spike findings converted to gates.

### 8.1 Hard gates (build fails)

1. `cavet-healthcheck` exits 0 in a fresh container.
2. Curated rule file count within [1700, 2100] (§4.4).
3. Offline staged scan completes: network-disconnected container, the three mandatory
   Trivy flags, fixture repo from `internal/finding/testdata/fixture/` — exit 0, SARIF
   produced (spike §4: without flags this fatals with `failed to download vulnerability
   DB`; with them it completed in 1.8 s with all planted findings).
4. No `UnicodeDecodeError` possible: locale env verified by running Opengrep against
   the fixture with an ASCII-forcing parent env.
5. `git -C /workspace log` works on a mounted repo without `safe.directory` errors.
6. All three scanners report their pinned versions matching §2.1 exactly.

### 8.2 Soft gates (warn, do not fail)

1. Uncompressed size > 3.2 GB core / 4.8 GB full — drift alarm, not a brick wall.
2. Rule count moved more than ±15% vs previous published image — signals an upstream
   restructure worth a human glance before rebaselining.

### 8.3 Multi-arch verification

Both architectures run gates 1, 3, 6. Architecture parity is cheap now (prebuilt
binaries exist for both) and expensive to retrofit after someone depends on arm64.

---

## 9. Build and publish flow

1. PR touching `engine/` → matrix build amd64+arm64, gates §8.1 on both.
2. Merge to main → nightly scheduled build catches upstream drift (new CVE data, rule
   corpus changes) without human cadence.
3. Publish: multi-arch manifest pushed as `core`/`full`; digest recorded into
   `docs/engine/digest.txt` (one line, reviewable diff — spec §7.5); release notes
   list scanner version deltas and rule-count movement.
4. Consumers adopt via `cavet engine pull` + `cavet rebaseline` — never by editing
   `config.yaml` by hand (cli-spec §5).

The nightly build publishing automatically is deliberate: staleness bounded by image
release cadence is spec §7.5's stated model, and a human bottleneck guarantees the
cadence dies.

---

## 10. Deviations and clarifications against SPECIFICATION.md

1. **Rule curation count assertion** (§4.4) — spec requires mechanical filtering; this
   annex adds the numeric guardrail that makes silent breakage a failed build.
2. **Checksum-verified binary downloads** (§3) — spec pins versions; checksums extend
   pinning to artifacts. Implied by §3.4, never stated.
3. **Nightly auto-publish** (§9) — spec says staleness is bounded by release cadence;
   this annex chooses the cadence. A manual-release workflow would satisfy the letter
   and kill the property in practice.
4. **Gitleaks stub config baked** (§3.1) — forward accommodation, zero behaviour
   today; noted so its presence is not mysterious later.
