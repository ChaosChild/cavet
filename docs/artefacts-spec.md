# cavet — Artefact Directory Specification

**Status:** Component annex to [`SPECIFICATION.md`](SPECIFICATION.md). Implementation-grade.
**Scope:** `.cavet/` as a data contract — schemas, algorithms, concurrency, corruption and
evolution policy, and the Go packages that own them.
**Date:** 2026-08-21

Where this annex specifies something `SPECIFICATION.md` leaves open or states differently,
the deviation is listed in §14 and the section here says so. Nothing here changes the
design of record; it pins it.

---

## 1. Layout

Lives at `.cavet/` in the repository root. Created only by `cavet init`.

```
.cavet/
  config.yaml              # operator configuration — committed
  .gitattributes           # log/*.jsonl merge=union — committed
  .gitignore               # state/, cache/, reports/ — committed
  log/
    events-2026-08.jsonl   # append-only, monthly rotation — committed
  state/
    findings.json          # derived
    items.json             # derived
    baseline.json          # derived
    lock                   # concurrency, §7 — never committed, never derived-meaningful
  cache/
    advisories/            # lookup results — gitignored
  design/
    threat-model.md        # produced by design skills — committed
    decisions/             # ADR-shaped decision records — committed
  reports/
    latest.sarif           # machine interchange — gitignored
```

**Committed:** `config.yaml`, `.gitattributes`, `.gitignore`, `log/`, `design/`.
Everything else is derived or transient. `cavet rebuild` recreates `state/` from `log/`;
`cache/` and `reports/` are disposable working data.

### 1.1 Exact scaffold contents

`.cavet/.gitattributes`:

```
log/*.jsonl merge=union
```

`.cavet/.gitignore`:

```
state/
cache/
reports/
```

Both live *inside* `.cavet/`, so their patterns are relative to it and cannot leak into
the host repository's own ignores. `cavet init` writes these files verbatim; a later
`init` does not overwrite operator edits — it reports drift and exits 0 (the files are
corrective suggestions, not runtime inputs).

---

## 2. The log

`log/events-YYYY-MM.jsonl` is the source of truth (spec §3.1). One JSON object per
line, UTF-8, LF-terminated. Append-only: no command ever rewrites, truncates, or
reorders a log file. Rotation is by calendar month of the event timestamp (UTC); the
filename is chosen at append time and never revisited. Reads glob `events-*.jsonl` in
lexicographic order, which is chronological order.

### 2.1 Event envelope, version 1

```json
{
  "ts": "2026-08-17T09:14:22Z",
  "v": 1,
  "event": "triaged",
  "fingerprint": "a3f9c2e41b77d0c8...",
  "actor": "agent",
  "phase": "build",
  "engine": "ghcr.io/cavet/cavet-engine@sha256:4f2a…",
  "data": { }
}
```

| Field | Type | Rules |
|---|---|---|
| `ts` | string | RFC 3339, UTC |
| `v` | int | Schema version, currently `1` (§10) |
| `event` | string | One of the nine kinds below |
| `fingerprint` | string | Full lowercase hex SHA-256 (64 chars). Required on `detected`, `triaged`, `surfaced`, `remediated`, `suppressed`, `deferred`. Absent on `raised`, `resolved`, `rebaselined` — for `raised` kind `verification`, the fingerprint travels in `data` (spec §3.1) |
| `actor` | string | `agent` \| `operator` |
| `phase` | string | `design` \| `build` \| `test` \| `deploy` |
| `engine` | string | Engine image reference with digest. Present on **every** event: all commands except `init`, `describe`, `engine pull` refuse to run against an uninitialised directory, so the digest is always known by the time anything is appended |

### 2.2 Event kinds and payloads

Nine kinds, matching spec §3.1. Payload shapes are normative; unknown *fields* within a
known payload are ignored on read (§10).

| Kind | Payload (`data`) | Notes |
|---|---|---|
| `detected` | `rule`, `severity`, `path`, `line`, `description`, `scanner`, `also_detected_by[]` | Emitted once per fingerprint, ever (spec §3.2). `path` is repository-relative, forward slashes. `severity` is already normalised (§2.3) |
| `triaged` | `verdict`, `confidence`, `reason`, `sources[]` | `verdict`: `confirmed`\|`dismissed`; `confidence`: `high`\|`low`; `reason` non-empty |
| `surfaced` | `context` | Where it was shown: `pre-commit`, `dispatch`, `posture` |
| `remediated` | `reason` | Gated by the CLI on originating-scanner coverage (spec §3.1, §5.2) |
| `suppressed` | `reason` | |
| `deferred` | `reason` | |
| `raised` | `kind`, `question`, `fingerprint?` | `kind`: `design`\|`verification`; `fingerprint` present iff `kind` is `verification` |
| `resolved` | `answer`, `sources[]` | |
| `rebaselined` | `from_digest`, `to_digest`, `reason` | |

`sources[]` elements are `{"id": "CVE-2021-44228", "url": "https://…"}` — identifier
plus canonical URL, the cite-or-omit contract of spec §8.

### 2.3 Severity

Scanners use incompatible scales. The CLI normalises at `detected`-emission time to:

`critical` | `high` | `medium` | `low` | `info`

Mapping per scanner is owned by the CLI annex (§ of `cli-spec.md`). Gitleaks emits no
severity; its findings map to `high` (a committed credential is high until triaged
otherwise). The raw scanner value survives in `reports/latest.sarif`.

---

## 3. `internal/events` — sole author of event shapes

No raw string literals for kinds, verdicts, confidences, severities, phases, actors,
or payload keys anywhere outside this package (spec §10.2). Validation happens at
construction, so an invalid event cannot exist, let alone reach disk.

```go
package events // internal/events

type Actor string
type Phase string
type Kind string
type Verdict string
type Confidence string
type ItemKind string
type Severity string
type SurfaceContext string // pre-commit | dispatch | posture

// …constants for every value above; see §2 for the value sets…

type Source struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// Data is the closed set of payload types. Each payload knows its kind, so
// marshalling and validation are total: there is no such thing as an
// Event whose payload disagrees with its envelope.
type Data interface{ dataKind() Kind }

type Event struct {
	TS          time.Time `json:"ts"`
	V           int       `json:"v"`
	Kind        Kind      `json:"event"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Actor       Actor     `json:"actor"`
	Phase       Phase     `json:"phase"`
	Engine      string    `json:"engine"`
	Data        Data      `json:"-"`
	// raw holds the canonical encoding of Data, produced at construction.
	raw []byte
}
```

Payload structs carry the JSON tags that define the on-disk names (§2.2), e.g.:

```go
type TriagedData struct {
	Verdict    Verdict    `json:"verdict"`
	Confidence Confidence `json:"confidence"`
	Reason     string     `json:"reason"`
	Sources    []Source   `json:"sources,omitempty"`
}

func (TriagedData) dataKind() Kind { return Triaged }
```

Constructors — one per kind, each validating and returning errors for empty reasons,
out-of-set values, malformed fingerprints, and payload/envelope disagreements:

```go
func NewDetected(ts time.Time, actor Actor, phase Phase, engine, fp string,
	d DetectedData) (Event, error)
func NewTriaged(ts time.Time, actor Actor, phase Phase, engine, fp string,
	d TriagedData) (Event, error)
// …NewSurfaced, NewRemediated, NewSuppressed, NewDeferred,
//   NewRaised, NewResolved, NewRebaselined…
```

`MarshalJSON` emits the envelope with `data` inlined from `raw`. Field order on disk is
struct order — deterministic, which §6 depends on.

`Canonical(e) []byte` returns that deterministic encoding. It is the input to replay
ordering and item-id derivation. Two events are duplicates iff their canonical forms are
byte-equal apart from `ts` (see §6.2).

---

## 4. `config.yaml` — normative schema

Format and validation live here; consumption lives in the CLI annex. All keys optional;
defaults shown. **Unknown keys are a parse error** (fail loud, spec §4.6). Values are
strictly typed; `true`/`false` only for booleans, no ambient coercion.

```yaml
engine:
  variant: core              # core | full — java-db inclusion (spec §7.2.1)
  digest: ""                 # explicit image ref; normally managed by
                             # `cavet engine pull` / `cavet rebaseline`
scan:
  deep_default: false        # staged/diff scans imply --deep (spec §5.2)
  container_images: false    # opt-in Docker socket mount (spec §7.6)
  hook_exit_1: false         # pre-commit hook exits 1 on findings instead of always 0
scanners:
  checkov: false             # extra IaC scanner (spec §7.2)
network:
  proxy: ""                  # passed through to the container (spec §7.5)
  db_overrides:              # mounted over the baked DBs when set (spec §7.5)
    trivy_db: ""
    trivy_java_db: ""
```

Notes:

- `engine.digest` is written by `cavet` itself during `init`/`pull`/`rebaseline`.
  Hand-editing it is allowed but pointless without `cavet rebaseline`, which is the only
  command that acts on a change.
- `network.db_overrides` exists to honour spec §7.5's promise of first-class offline DB
  paths for operators who mirror databases internally. When both are empty (default),
  the baked databases are used and nothing is mounted.

```go
package config // internal/config

type Config struct{ /* fields mirroring the YAML above */ }

func Load(path string) (Config, error) // parse + validate; unknown-key errors name the key
func Default() Config
```

---

## 5. `internal/fingerprint` — the algorithm, pinned

Spec §3.3 fixes the design; this fixes the bytes. Two independent identities exist:

**Finding fingerprint** — `sha256_hex(rule_key + "\x00" + normalised_context)`

- `rule_key` = the rule's CWE id (`CWE-89`) when the scanner supplies one, else the
  scanner's rule id (`generic-api-key`).
- `normalised_context` is produced by `Normalise`, below.
- Secrets are collapsed **before** this step (spec §3.3): when two scanners report the
  same secret, one `detected` event is written with `also_detected_by` recording the
  loser. The collapse key is
  `sha256_hex(normalised_matched_span + "\x00" + repo_relative_path)` — computed by
  `Secret`, never persisted (persisting it would duplicate the secret's location data
  into state).

```go
package fingerprint // internal/fingerprint

const ContextLines = 3

func RuleKey(cwe, ruleID string) string // cwe wins when non-empty
func Of(ruleKey, normalisedContext string) string // lowercase hex
func Secret(matchedSpan, repoPath string) string  // pre-collapse identity, hex
func Normalise(src []byte, matchLine int) (string, error)
```

`Normalise`, in order:

1. Decode UTF-8; invalid bytes become U+FFFD rather than failing — scanners do emit
   mojibake, and a crash here loses triage history over cosmetic damage.
2. CRLF and lone CR → LF.
3. Take lines `matchLine-3 … matchLine+3` inclusive (1-based, clamped).
4. Mask string literals — `'…'`, `"…"`, `` `…` `` → `«s»` (before numbers, so digits
   inside strings do not double-mask).
5. Mask numeric literals `\b[0-9]+(\.[0-9]+)?\b` → `«n»`.
6. Collapse every whitespace run (including newlines) to one space; trim.

`ponytail:` no Unicode normalisation (NFC/NFKC) at this layer — stdlib-only, and two
visually identical strings in different normal forms hash differently. Add
`golang.org/x/text/unicode/norm` step between 1 and 2 if real misses show up.

**Display ids.** Findings are addressed by the first 6 hex characters of the
fingerprint. If two live findings collide on 6 characters, both prefixes extend (7,
8, …) until distinct; the resolved `display_id` is stored in `state/findings.json`,
so commands never recompute it. Full hashes remain authoritative everywhere else.

---

## 6. Replay: `cavet rebuild`

`ReadLog()` parses every log file into events. `Rebuild()` then produces `state/` in
two phases.

### 6.1 Ordering

After a `merge=union` merge the physical line order is meaningless, so replay imposes a
total order: **sort by `(ts, canonical_bytes)`**. Deterministic regardless of file
order, chunking, or how many branches appended. Timestamp ties break on content, which
is stable because canonical encoding is byte-deterministic (§3).

### 6.2 Folding rules

| Event | Effect on state |
|---|---|
| `detected` | Insert finding if fingerprint unseen (duplicate canonical events collapse silently — expected after branch merges); record originating scanner, severity, description, locations; `detected_at` = first occurrence |
| `triaged` | Attach verdict to the finding; error if fingerprint unknown (a triage without its detection means a corrupted or partially-lost log — fail loud, §8) |
| `surfaced` | None. Presentation is history, not state |
| `remediated` | Remove the finding |
| `suppressed`, `deferred` | Set status accordingly |
| `raised` | Insert item; `items[].id` = `"it-" + first 8 hex of sha256(canonical(event))` — **content-derived**, because replay order is not stable enough to derive ids from sequence positions |
| `resolved` | Remove the item; error if unknown |
| `rebaselined` | See §6.3 |

Output is written atomically (temp file + rename, §7.3) after the whole replay succeeds.
A failed rebuild leaves the previous `state/` untouched.

### 6.3 Rebaseline semantics

`cavet rebaseline` (CLI annex owns the flow) runs a full scan itself, then:

1. Emits one `rebaselined` event (`from_digest`, `to_digest`, reason).
2. Writes `state/baseline.json` from the scan's fingerprints.
3. Preserves every existing verdict. Rebaseline regenerates debt accounting; it never
   fabricates or discards triage history (spec §3.3).
4. Marks untriaged findings `in_baseline: true` — they stop being "new" in deltas but
   remain visible via `cavet debt`.

### 6.4 The `last_seen` gap, stated honestly

`last_seen` is refreshed by scans (spec §3.2) but scans deliberately do not log
per-finding observations — that is the entire point of §3.2's one-event-per-fingerprint
rule. Therefore `last_seen` is **not** reconstructable from `log/` alone. Resolution:
`cavet scan` rewrites `state/findings.json` wholesale with fresh observations (it holds
them anyway), and `rebuild` reconstructs everything *except* freshness, setting
`last_seen = detected_at` for want of better data. Consequence: after a manual rebuild,
"is this still present?" answers from the next scan, which costs 1.8 s warm. This is a
measured trade against either a tenth event type (rejected by spec §8.1) or a
side-journal of raw observations (rejected as a second source of truth).

---

## 7. Concurrency and atomicity

Two writers are expected to overlap eventually — the §9 pre-commit hook and an agent
session share one working tree. Policy: **many readers, one writer, no exceptions.**

### 7.1 The lock

`.cavet/state/lock`, created with `O_CREATE|O_EXCL`, containing one JSON line:
`{"pid":1234,"ts":"2026-08-21T09:14:22Z"}`.

- Contention: retry every 100 ms up to 10 s, then fail exit 2 with
  `another cavet process holds the lock (pid N)` — never queue silently, never corrupt.
- Stale takeover: holder pid dead (signal-0 probe on POSIX, `OpenProcess` on Windows via
  `golang.org/x/sys/windows`, already in the dependency graph of the Docker SDK) **or**
  lock mtime older than 60 s → remove and recreate.
- `ponytail:` O_EXCL + pid liveness rather than OS-level flock — ~50 lines, zero new
  dependencies. Swap for `gofrs/flock` if stale-takeover misbehaves in practice.

Every mutating command holds the lock for its whole read-decide-append-write cycle:
`init`, `scan`, `triage`, `suppress`, `defer`, `raise`, `resolve`, `rebuild`,
`rebaseline`. Pure readers (`posture`, `finding`, `log`, `items`, `debt`, `describe`)
never take it.

### 7.2 Log appends

One event = one `Write` call of one `\n`-terminated line, file opened `O_APPEND`.
Under the lock this yields clean interleaving even if some future code path bypasses
it. No fsync per event — the log is committed VCS history, and the worst case for an
unclean shutdown is the partial-line case of §8, which is handled.

### 7.3 State writes

Temp file in the same directory, rename over target. Atomic per file on POSIX and
Windows (`MoveFileEx(REPLACE_EXISTING)` under Go's `os.Rename`). Readers may therefore
read `state/` lock-free and see either the old or the new file, never a torn one.
Cross-file consistency between `findings.json` and `items.json` is not attempted —
each is independently regenerated by replay (§6), and no consumer reads both and
requires agreement.

---

## 8. Corruption policy

The log is the source of truth, so silent repair is forbidden.

- **Malformed line** (bad JSON, schema violation, unknown `v`): hard error naming file
  and line number. Commands that read the log fail exit 2. Never skipped, never edited.
- **Trailing partial line** (no terminating newline — the crash-mid-append case):
  warning to stderr, ignored, left untouched on disk. The next append starts a fresh
  line.
- **Dangling references** found during replay (triage without detection, resolution
  without raise): hard error, same reporting. These indicate manual edits or real data
  loss; `cavet` is not the tool that quietly papers over them.

---

## 9. State file schemas

All three are derived; consumers other than `cavet` itself should treat them as opaque.

### 9.1 `state/findings.json`

```json
{
  "rebuilt_at": "2026-08-21T09:00:00Z",
  "findings": [
    {
      "fingerprint": "a3f9c2e41b77d0c8…",
      "display_id": "a3f9c2",
      "rule_key": "CWE-89",
      "rule_id": "py.sql-injection",
      "originating_scanner": "opengrep",
      "also_detected_by": [],
      "secret": false,
      "collapsed_with": [],
      "severity": "high",
      "description": "user input concatenated into query",
      "locations": [{ "path": "api/users.py", "line": 88 }],
      "detected_at": "2026-08-17T09:14:22Z",
      "last_seen": "2026-08-20T17:02:11Z",
      "status": "open",
      "verdict": null,
      "in_baseline": false
    }
  ]
}
```

- `status`: `open` | `confirmed` | `dismissed` | `deferred` | `suppressed`.
- `verdict`: the latest `triaged` payload plus `at` and `by` (actor), or `null`.
- `collapsed_with`: scanner rule ids folded in via secret dedup (mirrors
  `also_detected_by` on the event).
- `secret`: `true` when the fingerprint was produced from the secret-collapse path.
- Remediated findings are **removed**, not flagged — the log is their archive (§6.2).
- `in_baseline`: pre-existing debt (§6.3); excluded from "new" counts, included in
  `cavet debt`.

### 9.2 `state/items.json`

```json
{
  "rebuilt_at": "2026-08-21T09:00:00Z",
  "items": [
    {
      "id": "it-b7d21c0f",
      "kind": "verification",
      "question": "does the response middleware support masking…?",
      "fingerprint": "a3f9c2e41b77d0c8…",
      "raised_at": "2026-08-19T10:31:00Z",
      "raised_by": "agent"
    }
  ]
}
```

Open items only; resolution removes the entry (§6.2). `kind` mirrors the event's
`data.kind`.

### 9.3 `state/baseline.json`

```json
{
  "engine_digest": "ghcr.io/cavet/cavet-engine@sha256:4f2a…",
  "created_at": "2026-08-17T09:20:00Z",
  "fingerprints": ["a3f9c2e41b77d0c8…"]
}
```

Rewritten by `init` and `rebaseline` only.

---

## 10. Schema evolution

- `v` on every event (formalises spec §10.2's "schema version recorded on every
  event"). Current version: **1**.
- Readers compiled for version 1 **reject higher versions loudly** — a newer binary
  wrote this log; proceeding would misinterpret history. The error names both versions.
- Unknown fields within known payloads: ignored (forward-compatible additions).
- Unknown event kinds: preserved byte-for-byte through `rebuild`, excluded from the
  fold, counted in one summary warning. Nothing is silently discarded (spec §3.2), and
  an old binary never destroys what a new one wrote.
- Migrations, when `v` advances, will be replay transforms documented in this annex
  before the code exists.

---

## 11. Advisory cache — `cache/advisories/`

One file per identifier, filename = URL-safe-encoded identifier
(`CVE-2021-44228.json`, `pkg~1npm~1lodash@4.17.20.json`):

```json
{
  "identifier": "CVE-2021-44228",
  "fetched_at": "2026-08-20T12:00:00Z",
  "ttl_hours": 168,
  "payload": { }
}
```

- `payload` is whatever the source adapters return (CLI annex owns adapter shapes);
  this annex owns only the wrapper and expiry.
- Expiry: `fetched_at + ttl_hours` (168 h = one week, spec §5.3).
- Expired + online → refetch on demand. Expired + offline → **serve stale with an
  explicit stale marker in output**; degradation beats failure (spec §5.3).
- Written atomically (§7.3); never locked — a torn cache file is deleted and refetched.

---

## 12. Reports — `reports/latest.sarif`

One merged SARIF 2.1.0 document per scan, scanners that ran as `tool.driver` entries,
repository-relative paths. Overwritten atomically each scan; no history is kept here —
CI systems that want history archive the file themselves. Raw SARIF never reaches the
model (spec §4); this file exists for machines, not agents.

---

## 13. Go package map

| Package | Owns | Key exports |
|---|---|---|
| `internal/events` | Every constant, constructor, payload struct; canonical encoding | `Event`, `Data`, nine `New*` constructors, `Canonical` |
| `internal/store` | Locking, append, log parsing, replay/fold, atomic writes | `Open`, `Init`, `Lock`, `Append`, `ReadLog`, `Rebuild` |
| `internal/config` | `config.yaml` parse + validate | `Load`, `Default` |
| `internal/fingerprint` | Identity: rule keys, normalisation, hashing | `RuleKey`, `Of`, `Secret`, `Normalise` |

Dependency direction: `store → {events, config}`; `fingerprint` stands alone; nothing
imports downward from the CLI annex's packages except through these four.

---

## 14. Deviations and clarifications against SPECIFICATION.md

1. **`v` field added to the event envelope** (§2.1). Spec §10.2 says schema versions
   are "recorded on every event"; the field did not appear in the §3.1 example. The
   example there predates this annex and should gain `"v": 1` at next revision.
2. **`last_seen` is not log-reconstructable** (§6.4). Spec describes `state/` as fully
   derived from `log/`; `last_seen` is the one field that decays to `detected_at` on
   rebuild until the next scan. Recorded here as a deliberate exception rather than
   silently breaking the "derived" claim.
3. **Severity values enumerated** (§2.3) — five levels, normalised at emission; the
   spec shows examples but never fixes the set.
4. **`engine` mandatory on every event** (§2.1). Spec §3.4 says "recorded on every
   event"; this annex adds the reason it is always available: uninitialised directories
   refuse every appending command.
5. **Item ids are content-derived** (§6.2) — necessary once `merge=union` makes replay
   order non-authoritative; the spec is silent on item identity.
6. **`display_id` collision extension** (§5) — spec shows 6-hex ids without specifying
   collision behaviour.
