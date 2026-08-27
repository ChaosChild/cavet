# cavet — CLI Specification

**Status:** Component annex to [`SPECIFICATION.md`](SPECIFICATION.md). Implementation-grade.
**Scope:** the `cavet` binary — command surface, scan orchestration, projection,
engine client, lookup, machine contract, testing.
**Depends on:** [`artefacts-spec.md`](artefacts-spec.md) for the data contract.
**Date:** 2026-08-21

Deviations against SPECIFICATION.md are listed in §16. Nothing here changes the design
of record; it pins it.

---

## 1. Identity and distribution

- Module path: `github.com/ChaosChild/cavet` (org decision of spec §13.1 settled
  2026-08-25; repository private until v0.1 stabilises).
- Binary name: `cavet`. One static binary per platform: windows/amd64, linux/amd64,
  linux/arm64, darwin/amd64, darwin/arm64 via GitHub Releases (spec §10.1).
- Version string embedded at build (`-ldflags "-X main.version=…"`), reported by
  `cavet --version` and carried in `describe --json`.

## 2. Dependencies — total list

| Dependency | Why | What it buys |
|---|---|---|
| `github.com/spf13/cobra` | 16 subcommands with uniform `--help` | Help text, unknown-flag-fails-loud, completions — spec §2.1 makes help quality a requirement |
| `github.com/moby/moby/client` + `/api` | Container lifecycle | Official Docker SDK per spec §7; the SDK moved to moby/moby submodules in 2026 — same client, new module paths. `errdefs` classification comes from `github.com/containerd/errdefs`, already in the SDK's graph |
| `gopkg.in/yaml.v3` | `config.yaml` | Boring, sufficient |
| `golang.org/x/sys` | Windows pid liveness probe for the lock | Already in the Docker SDK's graph |

Nothing else. No SARIF library — the projection reads three known emitter shapes with
`encoding/json` structs; a general SARIF parser is a dependency buying nothing here
(§8). No git library — every git operation runs inside the container (§7.3), so the
host needs no git dependency at all.

## 3. Package layout

```
cmd/cavet/            main.go — wiring only
internal/cli/         cobra command definitions, flag plumbing
internal/scan/        scope resolution, tier selection, delta computation
internal/engineclient/ container lifecycle + exec plumbing (Docker SDK)
internal/projection/  SARIF → finding model → markdown rendering
internal/lookup/      five advisory adapters + cache integration
internal/describe/    machine contract emitter
internal/output/      aggregate lines, next-hints, error rendering
internal/events/      (artefacts annex)
internal/store/       (artefacts annex)
internal/config/      (artefacts annex)
internal/fingerprint/ (artefacts annex)
```

Dependency direction: `cli → {scan, describe, output}`; `scan → {engineclient,
projection, store, config, fingerprint}`; `lookup → store(cache), output`.
`engineclient` knows Docker and paths; it never parses findings. `projection` never
talks to Docker. Nobody below `cli` prints to stdout except through `output`.

---

## 4. Global behaviour

### 4.1 Exit codes (spec §4)

Informational, never gating:

| Code | Meaning |
|---|---|
| 0 | Success — including "0 new findings" |
| 1 | Findings present: the current result set contains ≥ 1 finding whose status is not `dismissed`/`suppressed` |
| 2 | Usage error or execution failure |

Only `scan` exits 1. Every other command exits 0 or 2.

### 4.2 Errors

One shape, stderr: `cavet: <message>` then, when a specific command owns the fix, a
second line `run 'cavet <command> --help'`. Structured causes are chained, not
dumped — a Docker daemon outage renders as
`cavet: docker daemon unreachable at <endpoint>; start Docker Desktop or set DOCKER_HOST`,
never as a stack trace (spec §7.6).

### 4.3 Initialisation gate

Every command except `init`, `describe`, `engine pull`, and `--version` refuses to run
without an initialised `.cavet/`: `cavet: no .cavet/ directory here; run 'cavet init'`.
Exit 2.

### 4.4 TTY refusal

`engine shell` checks stdin/stdout/stderr are all TTYs *before* contacting Docker and
refuses otherwise. This is what makes `cavet *` a safe subagent allowlist (spec §5).

### 4.5 Locking

Mutating commands take the artefact-directory lock (artefacts §7.1): `init`, `scan`,
`triage`, `suppress`, `defer`, `raise`, `resolve`, `rebuild`, `rebaseline`. Readers
never block.

---

## 5. Command reference

Flags not listed do not exist. Every command supports `--help`.

### `cavet` (bare)

Posture home view. Reads `state/`, prints: coverage header (last scan's scanners,
phase, engine digest from state), the confirmed-findings table (§9 rendering),
open-item count, baseline size. Exit 0 always — posture is a view, not a verdict.

### `cavet init [--hooks]`

1. Verify Docker reachable; pull engine image for `config.engine.variant`; record
   digest into `config.yaml`.
2. Start the long-lived container (§10).
3. Scaffold `.cavet/` exactly as artefacts §1.1.
4. Run one **full-tier** baseline scan (spec §5.1 pins this regardless of duration).
5. Emit `detected` events for everything found; write `baseline.json`;
   emit `rebaselined` with `from_digest` empty (initial).

   The long operations — image pull, container start, baseline scan — print progress
   to **stderr** as they advance (pull bytes and percentage, scan status), so a
   multi-minute first run is never silent. stdout stays clean; the final block below
   is the only stdout output.

6. Print exactly:

   ```
   initialised. 347 existing findings recorded as baseline.
   run `cavet debt` when you want to work through them.
   ```

Idempotent refusal if `.cavet/config.yaml` already exists (exit 2, say so). `--hooks`
additionally installs the pre-commit trigger (§13).

### `cavet scan [--staged|--diff <ref>|--full] [--deep] [--phase <phase>] [--context <ctx>]`

Exactly one scope flag; default is `--staged` when the index is non-empty, else
`--full` with a printed note. `--phase` defaults to `build` (§16). Full pipeline in §7. Emits `detected` / `remediated` /
`surfaced` events under the lock, rewrites `state/findings.json`, writes
`reports/latest.sarif`, prints the §9 result block. `--context` records the surfaced
payload (`pre-commit` used by the hook; default `dispatch`).

### `cavet finding <id> [--full]`

Display id lookup against `state/findings.json` (collision-resolved prefixes,
artefacts §5). Default: full row plus location list plus current verdict. `--full`
adds the complete event history for the fingerprint rendered as a compact table
(`cavet log --fingerprint` equivalent inline).

### `cavet triage <id> (--confirm|--dismiss) --reason "..." [--confidence high|low] [--source id=url]...`

Appends a `triaged` event, updates state. Empty `--reason` is a usage error. Omitting
`--confidence` is also a usage error — there is deliberately no default, because the
field exists precisely so the difference between verdicts is recorded (spec §6).

### `cavet suppress <id> --reason "..."` / `cavet defer <id> --reason "..."`

Append respective events, set status. Both require reasons; both are reversible only
by a later `triage`.

### `cavet raise --kind (design|verification) --question "..." [--fingerprint <id>]`

Appends `raised`; `--fingerprint` required iff kind `verification`. Prints the new
item id (`it-xxxxxxxx`) — the handle skills use with `resolve`.

### `cavet resolve <item-id> --answer "..." [--source id=url]...`

Appends `resolved`, removes the open item.

### `cavet debt [--severity <level>]`

Baseline table from `state/baseline.json` joined to `findings.json`, on demand only
(spec §5.1). Filter by normalised severity. Never printed by anything else.

### `cavet log [--since <date>] [--fingerprint <id>]`

Read-only log view. Default: last 50 events, newest first. Filters combine. Renders
one line per event: `ts · kind · short-fp · actor · reason/question excerpt`.

### `cavet lookup <identifier>... [--refresh]`

Identifiers only (spec §5.3): CVE/GHSA/OSV ids, purl coordinates
(`pkg:npm/lodash@4.17.20`), scanner rule ids, CWE ids. Anything unparseable is a usage
error naming the offending argument — that rejection *is* the no-leak guarantee.
Runs on the host, network-side; cache semantics per artefacts §11. Output: one compact
markdown table across all arguments (§11). Rule ids resolve locally from the engine
image's rule metadata — never a network call.

### `cavet items`

Open items table: id, kind, question, fingerprint link, raised_at, raised_by. Empty
state: `no open items`.

### `cavet engine (status|start|stop|pull|shell)`

- `status`: running/stopped, image digest vs configured digest (drift = explicit
  warning + `run 'cavet rebaseline'`), baked DB build date, warm/cold marker.
- `start`/`stop`: lifecycle control; `stop` removes the container (it holds no unique
  state — caches rebuild cold, which §12 documents).
- `pull`: fetch image for configured variant/digest; print old→new digests; does **not**
  rebaseline (that is deliberate and separate).
- `shell`: interactive shell in the container; TTY-gated (§4.4); refuses when the
  subagent allowlist pattern would reach it.

### `cavet rebuild`

Replay log → rewrite state (artefacts §6). Under the lock. Prints counts:
`replayed N events from M files; K findings, J items, baseline P.`

### `cavet rebaseline`

Flow per artefacts §6.3: refuse without Docker, run full scan, emit `rebaselined`,
rewrite `baseline.json`, mark untriaged findings `in_baseline`. Requires explicit
confirmation when invoked interactively (`--yes` for scripts); a subagent cannot be
asked, and rebaseline changes debt accounting — operator-only in practice.

### `cavet describe --json`

Machine contract for third-party installers (§12). Refuses without `--json` rather
than inventing a human format nobody asked for.

---

## 6. Scan tiers and scope resolution

| Invocation | Scanners | Target scanned |
|---|---|---|
| `--staged` | gitleaks, trivy | index content via checkout-index |
| `--diff <ref>` | gitleaks, trivy | current worktree content of files changed vs `<ref>` |
| `--full` | gitleaks, trivy, opengrep | `/workspace` (history + tree) |
| `--staged --deep` | gitleaks, trivy, opengrep | staged content |

`scan.deep_default` in config makes staged/diff imply `--deep`. There is no `--fast`
and no `--no-deep` (spec §5.2).

**Staged mechanics.** All git runs inside the container (host needs no git):

1. `git diff --cached --name-only -z` → staged paths (renames resolved to the new
   path). Empty → definitive `nothing staged` result, exit 0, no scan.
2. `git checkout-index --prefix=/scan/<n>/ --stdin` fed the path list → exact index
   blobs on disk. The scan describes what will be committed, not what sits in the
   working tree (spec §5.2).
3. Scanners target `/scan/<n>/`; results translate back by stripping the prefix.
4. `<n>` is a counter so concurrent-ish scans never share a temp dir; dirs die with
   the container.

**Diff mechanics.** `git diff --name-only -z <ref>` → copy each existing file from the
worktree mount into `/scan/<n>/` preserving relative directories; deleted files are
skipped silently (they cannot contain findings anymore).

---

## 7. Scanner invocation contracts

Exec'd into the long-lived container via the Docker SDK. Environment baked by the
image (UTF-8 locale etc., spec §7.2.1). Reports written to `/reports/<scanner>.sarif`
inside the container and copied out per scan.

### gitleaks

```
staged/diff:  gitleaks dir /scan/<n> --report-format sarif --report-path /reports/gitleaks.sarif --exit-code 0 --no-git
full:         gitleaks detect --source /workspace --report-format sarif --report-path /reports/gitleaks.sarif --exit-code 0
```

Exit 1 means leaks found (spike §6) — treated as results, not error. Severity maps to
`high` unconditionally (artefacts §2.3).

### trivy

```
trivy fs --scanners vuln,misconfig,secret \
  --skip-db-update --skip-check-update --offline-scan \
  --format sarif --output /reports/trivy.sarif \
  /scan/<n>          # or /workspace for full
```

The three offline flags are mandatory and emitted unconditionally — determinism before
offline support (spec §7.5). Severity: CRITICAL/HIGH/MEDIUM/LOW map verbatim;
UNKNOWN → `info`. Secret findings participate in cross-scanner collapse (§8.2).

### opengrep (deep tier only)

```
opengrep scan --config /opt/opengrep-rules \
  --sarif --output /reports/opengrep.sarif /scan/<n>   # or /workspace
```

Rule severity ERROR/WARNING/INFO → `high`/`medium`/`info`. CWE tags feed `rule_key`.

---

## 8. Delta computation

`internal/scan` merges per-scanner findings into one model, then folds against state.

### 8.1 Merge

Findings carry: rule id, rule key (CWE else rule id), severity (normalised), location,
description, originating scanner. Same-scanner duplicates (same fingerprint, several
locations) become one finding with multiple locations (spec §3.3).

### 8.2 Secret collapse

Before fingerprinting: secret-category findings (gitleaks all; trivy secret scanner)
whose `Secret(span, path)` keys match merge into one — first scanner wins the rule id,
loser recorded in `also_detected_by` / `collapsed_with`. The hand-built fixture pair
from spike §7 exercises this path (§15).

### 8.3 Fold rules

For each merged finding F with fingerprint f:

| Condition | Action |
|---|---|
| f in `findings.json` | refresh `last_seen`; no event |
| f in `baseline.json` only (post-rebuild gap) | insert into state, `in_baseline=true`; no event (its `detected` predates us) |
| unseen | append `detected` event; insert into state as `open` |

Then remediation pass over state findings **not** in this scan's result set:

| Condition | Action |
|---|---|
| originating scanner ran in this scan **and** every location's path was in scope **and** status ≠ `remediated-pending` | append `remediated`; remove from state |
| otherwise | retain silently |

A fast-tier scan can therefore never remediate an opengrep finding (spec §3.1). A
finding removed by remediation that later reappears gets a fresh `detected` event —
regressions reopen, deliberately.

Finally: one `surfaced` event with `--context`; atomic rewrite of
`state/findings.json`; merged SARIF written to `reports/latest.sarif`.

---

## 9. Projection — normative output

`internal/output` renders exactly this grammar (golden-tested, §15). Spec §4.1's block
is instance zero.

```
scan: <scope> · scanners: <csv> · phase: <p> · engine: cavet-engine@sha256:<8>
<confirmed-count> confirmed (<sev-breakdown>) · <dismissed> dismissed · baseline <b>

| id     | sev    | rule | location     | description              |
|--------|--------|------|--------------|--------------------------|
| a3f9c2 | high   | …    | api/x.py:88  | …                        |

next:
  cavet finding <id> --full
  cavet log --fingerprint <fp>
```

Rules:

- Header always names the scanners that actually ran (spec §4.1) — a clean result is
  meaningless otherwise.
- Columns fixed: 6-hex display id, severity, rule id, `path:line`, description
  truncated at 60 chars with ellipsis. One row per finding (multi-location shows the
  first path; count appended as `+N more` inside the cell).
- Sort: severity desc (critical first), then path asc, then line asc.
- Aggregate line always present. `baseline b` shown only after init-baseline exists.
- Confirmed-only rows by default; `--full` views add dismissed/suppressed/deferred
  with status column.
- Empty states are explicit strings, never silence: `0 new findings` /
  `no open items` / `nothing staged`.
- `next:` hints are concrete command templates chosen mechanically: confirmed rows
  exist → `cavet finding <top-id> --full`; any row → `cavet log --fingerprint <fp>`;
  baseline > 0 and not shown → `cavet debt`. At most three hints.
- Hints never reference skills or agents — the CLI speaks CLI.

SARIF parsing (in `internal/projection`): iterate `runs[].results[]`; resolve each
result's rule metadata lazily from `tool.driver.rules[ruleIndex]` on first reference
and memoise. The other 99.4% of the document is never touched (spike §5). Unknown
emitter quirks degrade to blank description cells, never parse failures — one
malformed result drops one row with a stderr warning naming the scanner.

---

## 10. Engine client

### 10.1 Container identity

Name: `cavet-<first 12 hex of sha256(abs repo root)>` — stable across sessions,
unique per repository, trivially greppable in `docker ps`. Image:
`ghcr.io/chaoschild/cavet-engine` with variant tag and pinned digest from
`config.engine.digest`.

### 10.2 Lifecycle

- Start: create if absent (bind-mount repo root at `/workspace`, `network` disabled
  except when `network.proxy` is set), start, wait for health probe
  (`exec` `cavet-healthcheck` script shipped in the image: verifies all three scanner
  binaries respond to `--version`). Timeout 30 s cold.
- Before every scan: cheap probe (`docker inspect` state + version exec). Stopped →
  restart transparently (spec §7.1). Wrong digest → hard stop with the rebaseline
  instruction, never silent scanning on a stale engine.
- No idle timeout (spec §7.1); `engine stop` is the off switch.

### 10.3 Exec plumbing

`ContainerExecCreate` + `AttachOutput`; env/workdir per invocation contract; report
files retrieved with `ContainerCopyFromContainer` into memory (they are megabytes at
worst, spike §5) and discarded after projection. Scanner stderr is captured and
surfaced only on anomaly (non-zero exit without SARIF) — quiet success is the default.

### 10.4 Host↔container path translation

Bidirectional, table-driven, owned by `engineclient`:

| Direction | Rule |
|---|---|
| host → container | repo root ↔ `/workspace`; `C:\repo\api\x.py` → `/workspace/api/x.py` (case-preserving, separator-normalising) |
| staged temp | `/scan/<n>/<rel>` → `<rel>` |
| SARIF output | already repository-relative from scanners; verified, not rewritten |
| Linux uid | `--user $(uid):$(gid)` passed on linux hosts so `.cavet/` writes from the container are user-owned (spec §7.4) |

Windows long paths: temp staging uses the `\\?\` prefix internally; translated outputs
are always clean relative paths.

---

## 11. Lookup adapters

Five thin clients in `internal/lookup`, **deliberately without a shared interface**
(spec §5.3: a source that breaks is a contained repair). Each adapter returns its own
concrete struct; the renderer normalises for display only.

| Adapter | Endpoint(s) | Auth | Notes |
|---|---|---|---|
| osv | `POST api.osv.dev/v1/querybatch`, `/v1/vulns/{id}` | none | primary advisory source |
| kev | CISA known-exploited JSON feed | none | whole-feed fetch cached daily |
| epss | `GET api.first.org/data/v1/epss?cve=` | none | score only |
| nvd | `GET services.nvd.nist.gov/rest/json/cves/2.0` | optional key via `NVD_API_KEY` env | supplementary CVSS vectors |
| registry | npm / PyPI / crates.io / Go module proxy JSON APIs | none | existence, deprecation, last publish; dispatch on purl type |

Shared client behaviour (small helpers, not an abstraction layer): 10 s timeout per
request, one retry after 1 s on 429/5xx, then degraded. Degradation renders as an
explicit `not available` cell on the affected row — never silent omission, never exit
2 (spec §5.3). Cache read/write through artefacts §11; `--refresh` bypasses reads.
Scan-time enrichment reads cache only and marks uncached identifiers rather than
blocking the fast path.

Rule-id lookups (`cavet lookup py.sql-injection`) read the rule catalogue baked into
the engine image — extracted once per engine digest into
`cache/advisories/rules-<digest-prefix>.json` by `engine pull`. Local, offline,
version-exact.

---

## 12. `describe --json` schema

```json
{
  "cavet_version": "0.1.0",
  "log_schema_version": 1,
  "engine": {
    "image": "ghcr.io/chaoschild/cavet-engine",
    "variant": "core",
    "digest": "sha256:…"
  },
  "skills": [
    {
      "name": "cavet-design",
      "phase": "design",
      "recommended_path": "<skills-dir>/cavet-design"
    }
  ],
  "subagent": {
    "name": "cavet-security",
    "tools": ["Read", "Shell(cavet *)"],
    "definition": "<installers-url>/subagents/cavet-security.md"
  },
  "commands": ["items", "raise", "resolve", "scan", "triage", "lookup", "defer", "finding", "log"],
  "triggers": [
    {
      "name": "pre-commit",
      "install_command": "cavet init --hooks",
      "invocation": "cavet scan --staged --context pre-commit"
    }
  ],
  "config_keys": ["engine.variant", "scan.deep_default", "scanners.checkov"]
}
```

`--skills-dir <dir>` overrides `recommended_path` prefix so installers can render
harness-specific layouts from one source. Schema additions are additive-only; removals
bump `cavet_version` major.

---

## 13. Pre-commit hook installation

`init --hooks` sets `core.hooksPath=.cavet/hooks` and writes `.cavet/hooks/pre-commit`:

```sh
#!/bin/sh
exec cavet scan --staged --context pre-commit
```

Advisory-only behaviour is enforced inside `scan --context pre-commit` itself (hook mode
always exits 0 unless `config.scan.hook_exit_1` — added to the artefacts config table —
says otherwise). Windows: the hook file is a POSIX shim executed by Git for Windows'
bundled sh; a `.cmd` fallback invoking the binary directly is installed alongside and
day-one verification covers both (spec §9).

---

## 14. Concurrency integration

`scan` takes the lock once around [delta fold + event appends + state rewrite]; the
container exec happens *outside* the lock — two overlapping scans double-exec the
scanners (wasteful, harmless) rather than serialising 50 s deep scans behind each
other. Event appends remain conflict-free because only lock holders append.

---

## 15. Testing strategy

- **Golden files** for every §9 rendering branch, committed under
  `internal/output/testdata/golden/`. Instance zero is spec §4.1 verbatim.
- **Projection fixtures**: the spike's captured SARIF in `internal/finding/testdata/`
  feeds parse/fingerprint tests end-to-end — real emitters, not synthetic JSON.
- **Secret-collapse pair**: hand-built minimal two-SARIF pair reporting one secret
  under two rule ids (the consequence recorded in spike §7 — no committed fixture can
  exercise this naturally).
- **Replay round-trip**: log fixtures including a simulated post-`merge=union` shuffle
  must produce byte-identical `state/` (artefacts §6.1 determinism, tested where it
  hurts).
- **Lock contention**: two goroutines racing mutating commands — exactly one wins per
  critical section, loser times out with exit 2.
- **Adapter contract tests** run against recorded HTTP fixtures (offline CI), one file
  per source, no live-network tests in the suite.

---

## 16. Deviations and clarifications against SPECIFICATION.md

1. **`--confidence` has no default** (§5). Spec §6 requires confidence be recorded but
   never says what happens when it is omitted; omission is a usage error here.
2. **`--context` flag on `scan`** (§5) — the `surfaced` event's payload needs a source;
   the spec defines the event but not how context values arise.
3. **Hook exit policy moved into `scan`** (§13) with a `scan.hook_exit_1` config key;
   spec §9's "exits 0 regardless unless the operator configures otherwise" gains its
   configuration home.
4. **Staged scans skip git history** — `gitleaks dir` (content-only) rather than
   `detect` (history). Spec §7.2 notes Gitleaks "requires git history" without
   distinguishing tiers; staged content scanning cannot and should not walk history.
5. **Engine-digest drift is a hard stop**, not a warning (§10.2) — spec §3.4 calls the
   digest the basis of reproducibility; scanning anyway would betray it. The softer
   wording elsewhere is superseded here.
6. **`describe` refuses without `--json`** (§5) — spec names only the JSON contract;
   this annex declines to invent a second, human format that would drift.
7. **`--phase` defaults to `build`** (§5) — decided 2026-08-25. The spec requires a
   phase on every event but names no default for scan; `build` is the common case.
8. **`init` prints progress to stderr** (§5) — decided 2026-08-25. Spec §5.1 pins the
   two-line final output; nothing pins what precedes it, and minutes of silence during
   a 3 GB pull is how first runs die.
9. **Digest shown as 4 hex + ellipsis** (§9) — spec §4.1's instance zero prints
   `sha256:4f2a…`; that beats this section's `<8>` shorthand, which was illustrative.
10. **Aggregate line carries `N new suppressions`** (§9) — present in spec §4.1's
    instance zero, absent from the grammar above; the grammar is extended to match the
    instance rather than the other way round.
11. **Table columns pad to max cell width** (§9) — spec §4.1's hand-set widths are
    normalised to one consistent rule; cell content and order are unchanged.
12. **Projection strips the scan target prefix** (§9) — measured SARIF contradicts
    §10.4's "already repository-relative": Opengrep emits absolute paths under the
    scanned target (`/workspace/…`, `uriBaseId %SRCROOT%`); Gitleaks and Trivy emit
    relative ones. `Parse` takes the target path and strips it where present.
13. **Rule resolution by index or id** (§9) — only Trivy supplies `ruleIndex`;
    Gitleaks and Opengrep reference rules by `ruleId`. Resolution tries the index,
    falls back to an id map built once per document.
14. **Fingerprint context comes from the matched region only** (§8) — SARIF carries
    the region snippet, not surrounding lines, so spec §3.3's "surrounding context"
    cannot be honoured at parse time. Identical matched lines in different contexts
    merge into one finding with several locations — spec §3.3's intended reading.
    Revisit only if the engine grows a context-fetch step.
15. **`--no-git` dropped from the gitleaks `dir` invocation** (§7) — measured against
    gitleaks 8.30.1: the `dir` subcommand has no such flag (it is non-git by
    construction) and rejects it with a usage dump. The staged/diff contract is
    `gitleaks dir /scan/<n> --report-format sarif --report-path /reports/gitleaks.sarif
    --exit-code 0`. The full-scan `detect` invocation is unchanged.
