# cavet Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `cavet` v0.1.0 — the Go CLI, the engine OCI image, and the harness installers specified in [`SPECIFICATION.md`](SPECIFICATION.md) and its four annexes (`artefacts-spec.md`, `cli-spec.md`, `engine-spec.md`, `skills-spec.md`).

**Architecture:** A thin Go orchestrator (`cmd/cavet`) that owns an append-only JSONL log under `.cavet/`, drives scanners inside a digest-pinned OCI container via the Docker SDK, and projects SARIF into compact markdown. Judgement lives in six pre-drafted agent skills; the CLI is the only author of artefacts.

**Tech Stack:** Go 1.22+, cobra, Docker SDK, gopkg.in/yaml.v3, golang.org/x/sys; Dockerfile (debian:bookworm-slim) hosting Opengrep/Gitleaks/Trivy/git.

---

## Conventions for every task

- Primary dev platform is **Windows**; all shell commands are pwsh-compatible. Use `go test ./...` at each phase boundary.
- TDD throughout: test first, watch it fail, minimal implementation, watch it pass, commit.
- Commit messages follow conventional commits (`feat:`, `test:`, `chore:`, `docs:`).
- Every package lives under `internal/`; nothing outside `cmd/cavet` imports `main`.
- When a step says *Run* and gives expected output, actually run it and compare.
- Module path: `github.com/ChaosChild/cavet` (settled 2026-08-25; repo private until v0.1 stabilises).

## File structure map

```
go.mod, .golangci.yml, .github/workflows/ci.yml
engine/Dockerfile, engine/entrypoint.sh, engine/healthcheck, engine/LICENSES.md,
engine/curate-rules.sh, engine/digest.txt, engine/build.ps1
cmd/cavet/main.go
internal/fingerprint/{fingerprint.go}
internal/events/{events.go, payloads.go, constructors.go, canonical.go}
internal/config/{config.go}
internal/store/{store.go, lock.go, lock_windows.go, lock_unix.go,
                log.go, rebuild.go, atomic.go}
internal/output/{render.go, testdata/golden/*.md}
internal/projection/{sarif.go, severity.go, merge.go, testdata/...}
internal/engineclient/{client.go, exec.go, paths.go}
internal/scan/{scope.go, pipeline.go, delta.go}
internal/lookup/{osv.go, kev.go, epss.go, nvd.go, registry.go, cache.go, render.go}
internal/describe/{describe.go}
internal/cli/{root.go, init.go, scan.go, finding.go, triage.go,
              lifecycle.go, items.go, logdebt.go, rebuild.go,
              engine.go, hook.go, lookup.go, describe.go}
scripts/smoke.ps1
installers/{claude-code.ps1, codex.ps1, opencode.ps1, pi.ps1, hermes.ps1}
(existing) internal/finding/testdata/  # spike SARIF fixtures — read-only inputs
```

Phases are independently shippable: P1–P6 are pure libraries with no Docker dependency; P7 makes scans runnable end-to-end.

---

## Phase 0 — Scaffold

### Task 1: Module, lint config, CI

**Files:**
- Create: `go.mod`, `.golangci.yml`, `.github/workflows/ci.yml`, `.gitignore`

- [x] **Step 1: Init module**

```pwsh
go mod init github.com/ChaosChild/cavet
go get github.com/spf13/cobra@latest
go get github.com/docker/docker@latest
go get gopkg.in/yaml.v3@latest
go get golang.org/x/sys@latest
go mod tidy
```

Expected: `go.mod` lists the four direct deps.

- [x] **Step 2: `.gitignore`**

```gitignore
cavet
cavet.exe
dist/
```

(Note: repo-root gitignore; `.cavet/` ignores are created by `cavet init` itself.)

- [x] **Step 3: `.golangci.yml`**

```yaml
linters:
  enable: [errcheck, govet, staticcheck, revive, misspell]
issues:
  exclude-rules:
    - path: _test\.go
      linters: [errcheck]
```

- [x] **Step 4: `.github/workflows/ci.yml`**

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix: { os: [ubuntu-latest, windows-latest] }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go build ./...
      - run: go vet ./...
      - run: go test ./...
      - uses: golangci/golangci-lint-action@v6
        with: { args: --timeout=5m }
```

- [x] **Step 5: Verify and commit**

Run: `go build ./... && go vet ./...`
Expected: no output, exit 0.

```pwsh
git add go.mod go.sum .gitignore .golangci.yml .github
git commit -m "chore: scaffold Go module, lint config, CI"
```

---

## Phase 1 — `internal/fingerprint`

### Task 2: Normalisation

**Files:**
- Create: `internal/fingerprint/fingerprint.go`
- Test: `internal/fingerprint/fingerprint_test.go`

- [x] **Step 1: Write failing tests**

```go
package fingerprint

import "testing"

func TestNormaliseMasksAndCollapses(t *testing.T) {
	src := []byte("line1\nquery = \"SELECT * FROM users WHERE id = 42\"\nline3\nline4\nline5")
	got, err := Normalise(src, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := "line1 query = «s» line3 line4 line5"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormaliseContextWindowClamps(t *testing.T) {
	_, err := Normalise([]byte("x"), 0)
	if err == nil {
		t.Fatal("matchLine 0 must error")
	}
	got, err := Normalise([]byte("a"), 1)
	if err != nil || got != "a" {
		t.Fatalf(`got %q err %v`, got, err)
	}
}

func TestNormaliseCRLFAndInvalidUTF8(t *testing.T) {
	src := []byte{'a', 'b', '\r', '\n', 0xff, 'x'}
	got, err := Normalise(src, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != "ab \uFFFDx" {
		t.Fatalf("got %q", got)
	}
}
```

- [x] **Step 2: Run to verify failure**

Run: `go test ./internal/fingerprint/ -v`
Expected: FAIL (undefined: Normalise).

- [x] **Step 3: Implement**

```go
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const ContextLines = 3

var (
	reStrings = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|` + "`" + `[^` + "`" + `]*` + "`")
	reNumbers = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	reWS      = regexp.MustCompile(`\s+`)
)

// RuleKey prefers the CWE mapping; scanner rule ids are the fallback (spec §3.3).
func RuleKey(cwe, ruleID string) string {
	if cwe != "" {
		return cwe
	}
	return ruleID
}

func Of(ruleKey, normalisedContext string) string {
	h := sha256.Sum256([]byte(ruleKey + "\x00" + normalisedContext))
	return hex.EncodeToString(h[:])
}

func Secret(matchedSpan, repoPath string) string {
	h := sha256.Sum256([]byte(matchedSpan + "\x00" + repoPath))
	return hex.EncodeToString(h[:])
}

// ponytail: no NFC normalisation — add x/text between decode and CRLF fold
// only if real-world misses show up (artefacts §5).
func Normalise(src []byte, matchLine int) (string, error) {
	if matchLine < 1 {
		return "", fmt.Errorf("matchLine must be >= 1, got %d", matchLine)
	}
	s := strings.ToValidUTF8(string(src), "\uFFFD")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	start := matchLine - 1 - ContextLines
	if start < 0 {
		start = 0
	}
	end := matchLine - 1 + ContextLines
	if end > len(lines)-1 {
		end = len(lines)-1
	}
	ctx := strings.Join(lines[start:end+1], "\n")
	ctx = reStrings.ReplaceAllString(ctx, "«s»")
	ctx = reNumbers.ReplaceAllString(ctx, "«n»")
	ctx = reWS.ReplaceAllString(ctx, " ")
	return strings.TrimSpace(ctx), nil
}
```

- [x] **Step 4: Run to verify pass**

Run: `go test ./internal/fingerprint/ -v`
Expected: PASS.

- [x] **Step 5: Cross-check hash vector against coreutils**

```pwsh
"go on`0ctx" | Out-File -NoNewline /tmp/v.bin; sha256sum /tmp/v.bin   # WSL or Git Bash
```

Then in a scratch Go test assert `Of("go","ctx")` equals that hex. Delete the scratch test afterwards.

- [x] **Step 6: Commit**

```pwsh
git add internal/fingerprint
git commit -m "feat(fingerprint): rule keys, secret identity, pinned normalisation"
```

---

## Phase 2 — `internal/events`

### Task 3: Constants, payloads, canonical encoding

**Files:**
- Create: `internal/events/events.go`, `payloads.go`, `canonical.go`
- Test: `internal/events/events_test.go`

- [x] **Step 1: Failing test — canonical form is deterministic and shaped like artefacts §2.1**

```go
package events

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTriagedCanonicalShape(t *testing.T) {
	ts := time.Date(2026, 8, 17, 9, 14, 22, 0, time.UTC)
	ev, err := NewTriaged(ts, ActorAgent, PhaseBuild, "ghcr.io/x@sha256:a", fp64(), TriagedData{
		Verdict: VerdictDismissed, Confidence: ConfidenceHigh,
		Reason: "test fixture", Sources: []Source{{ID: "GHSA-x", URL: "https://g"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var any map[string]json.RawMessage
	if err := json.Unmarshal(Canonical(ev), &any); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ts", "v", "event", "fingerprint", "actor", "phase", "engine", "data"} {
		if _, ok := any[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	if string(any["event"]) != `"triaged"` || string(any["v"]) != "1" {
		t.Errorf("bad envelope: %s", Canonical(ev))
	}
	if Canonical(ev) == nil || len(Canonical(ev)) == 0 {
		t.Error("nil canonical")
	}
}

func fp64() string { return "a3f9c2e41b77d0c8a3f9c2e41b77d0c8a3f9c2e41b77d0c8a3f9c2e41b77d0c8" }
```

- [x] **Step 2: Run → FAIL** (`go test ./internal/events/ -v`)

- [x] **Step 3: Implement `events.go`**

```go
package events

import "time"

type (
	Actor        string
	Phase        string
	Kind         string
	Verdict      string
	Confidence   string
	ItemKind     string
	Severity     string
	SurfaceContext string
)

const (
	ActorAgent    Actor = "agent"
	ActorOperator Actor = "operator"

	PhaseDesign Phase = "design"
	PhaseBuild  Phase = "build"
	PhaseTest   Phase = "test"
	PhaseDeploy Phase = "deploy"

	Detected    Kind = "detected"
	Triaged     Kind = "triaged"
	Surfaced    Kind = "surfaced"
	Remediated  Kind = "remediated"
	Suppressed  Kind = "suppressed"
	Deferred    Kind = "deferred"
	Raised      Kind = "raised"
	Resolved    Kind = "resolved"
	Rebaselined Kind = "rebaselined"

	VerdictConfirmed Verdict = "confirmed"
	VerdictDismissed Verdict = "dismissed"

	ConfidenceHigh Confidence = "high"
	ConfidenceLow  Confidence = "low"

	ItemDesign       ItemKind = "design"
	ItemVerification ItemKind = "verification"

	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"

	ContextPreCommit SurfaceContext = "pre-commit"
	ContextDispatch  SurfaceContext = "dispatch"
	ContextPosture   SurfaceContext = "posture"
)

var SchemaVersion = 1

type Event struct {
	TS          time.Time
	V           int
	Kind        Kind
	Fingerprint string
	Actor       Actor
	Phase       Phase
	Engine      string
	payload     Data
	raw         []byte // canonical payload JSON, fixed at construction
}
```

- [x] **Step 4: Implement `payloads.go`** — closed set of nine payloads:

```go
package events

import "encoding/json"

type Data interface{ dataKind() Kind }

type Source struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type DetectedData struct {
	Rule           string   `json:"rule"`
	Severity       Severity `json:"severity"`
	Path           string   `json:"path"`
	Line           int      `json:"line"`
	Description    string   `json:"description"`
	Scanner        string   `json:"scanner"`
	AlsoDetectedBy []string `json:"also_detected_by,omitempty"`
}
type TriagedData struct {
	Verdict    Verdict    `json:"verdict"`
	Confidence Confidence `json:"confidence"`
	Reason     string     `json:"reason"`
	Sources    []Source   `json:"sources,omitempty"`
}
type SurfacedData struct {
	Context SurfaceContext `json:"context"`
}
type RemediatedData struct{ Reason string `json:"reason"` }
type SuppressedData struct{ Reason string `json:"reason"` }
type DeferredData struct{ Reason string `json:"reason"` }
type RaisedData struct {
	Kind        ItemKind `json:"kind"`
	Question    string   `json:"question"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}
type ResolvedData struct {
	Item    string   `json:"item"` // open-item id being closed (it-xxxxxxxx)
	Answer  string   `json:"answer"`
	Sources []Source `json:"sources,omitempty"`
}
type RebaselinedData struct {
	FromDigest string `json:"from_digest"`
	ToDigest   string `json:"to_digest"`
	Reason     string `json:"reason"`
}

func (DetectedData) dataKind() Kind    { return Detected }
func (TriagedData) dataKind() Kind     { return Triaged }
func (SurfacedData) dataKind() Kind    { return Surfaced }
func (RemediatedData) dataKind() Kind  { return Remediated }
func (SuppressedData) dataKind() Kind  { return Suppressed }
func (DeferredData) dataKind() Kind    { return Deferred }
func (RaisedData) dataKind() Kind      { return Raised }
func (ResolvedData) dataKind() Kind    { return Resolved }
func (RebaselinedData) dataKind() Kind { return Rebaselined }

var _ = json.Marshal // silence import if unused by linters during early commits
```

- [x] **Step 5: Implement constructors + canonical in `constructors.go` / `canonical.go`**

```go
package events

import (
	"encoding/json"
	"fmt"
	"time"
)

func validFp(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, r := range fp {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func build(ts time.Time, actor Actor, phase Phase, engine, fp string, d Data) (Event, error) {
	e := Event{TS: ts.UTC(), V: SchemaVersion, Kind: d.dataKind(),
		Fingerprint: fp, Actor: actor, Phase: phase, Engine: engine, payload: d}
	if fp != "" && !validFp(fp) {
		return e, fmt.Errorf("%s: malformed fingerprint %q", e.Kind, fp)
	}
	switch actor {
	case ActorAgent, ActorOperator:
	default:
		return e, fmt.Errorf("bad actor %q", actor)
	}
	switch phase {
	case PhaseDesign, PhaseBuild, PhaseTest, PhaseDeploy:
	default:
		return e, fmt.Errorf("bad phase %q", phase)
	}
	if engine == "" {
		return e, fmt.Errorf("%s: engine digest required (artefacts §2.1)", e.Kind)
	}
	var err error
	if e.raw, err = json.Marshal(d); err != nil {
		return e, err
	}
	return e, nil
}

func NewDetected(ts time.Time, actor Actor, phase Phase, eng, fp string, d DetectedData) (Event, error) {
	if d.Rule == "" || d.Path == "" || d.Scanner == "" || !validSeverity(d.Severity) || d.Line < 1 {
		return Event{}, fmt.Errorf("detected: incomplete payload %+v", d)
	}
	return build(ts, actor, phase, eng, fp, d)
}

func NewTriaged(ts time.Time, actor Actor, phase Phase, eng, fp string, d TriagedData) (Event, error) {
	if d.Reason == "" {
		return Event{}, fmt.Errorf("triaged: reason required")
	}
	if d.Verdict != VerdictConfirmed && d.Verdict != VerdictDismissed {
		return Event{}, fmt.Errorf("triaged: verdict %q", d.Verdict)
	}
	if d.Confidence != ConfidenceHigh && d.Confidence != ConfidenceLow {
		return Event{}, fmt.Errorf("triaged: confidence %q", d.Confidence)
	}
	return build(ts, actor, phase, eng, fp, d)
}

func NewSurfaced(ts time.Time, actor Actor, phase Phase, eng, fp string, d SurfacedData) (Event, error) {
	switch d.Context {
	case ContextPreCommit, ContextDispatch, ContextPosture:
	default:
		return Event{}, fmt.Errorf("surfaced: context %q", d.Context)
	}
	return build(ts, actor, phase, eng, fp, d)
}

func reasonEvent(kind func(string, time.Time, Actor, Phase, string, string, Data) (Event, error),
	reason string, rest ...any) {}

// NewRemediated/NewSuppressed/NewDeferred share shape:
func newReasoned(k Kind, ts time.Time, actor Actor, phase Phase, eng, fp, reason string) (Event, error) {
	if reason == "" {
		return Event{}, fmt.Errorf("%s: reason required", k)
	}
	var d Data
	switch k {
	case Remediated:
		d = RemediatedData{Reason: reason}
	case Suppressed:
		d = SuppressedData{Reason: reason}
	case Deferred:
		d = DeferredData{Reason: reason}
	default:
		return Event{}, fmt.Errorf("kind %s not reasoned", k)
	}
	return build(ts, actor, phase, eng, fp, d)
}

func NewRemediated(ts time.Time, a Actor, p Phase, e, fp, reason string) (Event, error) {
	return newReasoned(Remediated, ts, a, p, e, fp, reason)
}
func NewSuppressed(ts time.Time, a Actor, p Phase, e, fp, reason string) (Event, error) {
	return newReasoned(Suppressed, ts, a, p, e, fp, reason)
}
func NewDeferred(ts time.Time, a Actor, p Phase, e, fp, reason string) (Event, error) {
	return newReasoned(Deferred, ts, a, p, e, fp, reason)
}

func NewRaised(ts time.Time, a Actor, p Phase, e string, d RaisedData) (Event, error) {
	if d.Question == "" {
		return Event{}, fmt.Errorf("raised: question required")
	}
	if d.Kind != ItemDesign && d.Kind != ItemVerification {
		return Event{}, fmt.Errorf("raised: kind %q", d.Kind)
	}
	fp := ""
	if d.Kind == ItemVerification {
		fp = d.Fingerprint // travels in data per spec §3.1; envelope stays empty
		if !validFp(fp) {
			return Event{}, fmt.Errorf("raised verification: fingerprint required")
		}
	} else if d.Fingerprint != "" {
		return Event{}, fmt.Errorf("raised design: fingerprint forbidden")
	}
	return build(ts, a, p, e, "", d)
}

func NewResolved(ts time.Time, a Actor, p Phase, e string, d ResolvedData) (Event, error) {
	if !validItemID(d.Item) {
		return Event{}, fmt.Errorf("resolved: item id required (it-xxxxxxxx)")
	}
	if d.Answer == "" {
		return Event{}, fmt.Errorf("resolved: answer required")
	}
	return build(ts, a, p, e, "", d)
}

func NewRebaselined(ts time.Time, a Actor, p Phase, e string, d RebaselinedData) (Event, error) {
	if d.FromDigest == "" || d.ToDigest == "" || d.Reason == "" {
		return Event{}, fmt.Errorf("rebaselined: digests and reason required")
	}
	return build(ts, a, p, e, "", d)
}

func validSeverity(s Severity) bool {
	switch s {
	case SevCritical, SevHigh, SevMedium, SevLow, SevInfo:
		return true
	}
	return false
}
```

```go
// canonical.go
package events

import (
	"bytes"
	"encoding/json"
)

type envelope struct {
	TS          json.RawMessage `json:"ts"`
	V           int             `json:"v"`
	Kind        Kind            `json:"event"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Actor       Actor           `json:"actor"`
	Phase       Phase           `json:"phase"`
	Engine      string          `json:"engine"`
	Data        json.RawMessage `json:"data"`
}

func Canonical(e Event) []byte {
	ts, _ := json.Marshal(e.TS.UTC().Format(time.RFC3339)) // RFC3339 via encoding/json default
	env := envelope{
		TS: ts, V: e.V, Kind: e.Kind, Fingerprint: e.Fingerprint,
		Actor: e.Actor, Phase: e.Phase, Engine: e.Engine, Data: e.raw,
	}
	out, _ := json.Marshal(env)
	return out
}

var _ = bytes.MinRead
```

Note: drop the two `var _ =` silencer lines if unused after wiring imports properly — they exist only so intermediate commits compile; remove them in the same task's final pass.

- [x] **Step 6: Add validation-table test** covering one rejection per constructor:

```go
func TestConstructorRejections(t *testing.T) {
	ts := time.Now(); a := ActorAgent; p := PhaseBuild; e := "ghcr.io/x@sha256:a"; f := fp64()
	cases := []struct {
		name string
		fn   func() error
	}{
		{"triaged empty reason", func() error { _, err := NewTriaged(ts, a, p, e, f, TriagedData{Verdict: VerdictConfirmed, Confidence: ConfidenceLow}); return err }},
		{"triaged bad confidence", func() error { _, err := NewTriaged(ts, a, p, e, f, TriagedData{Verdict: VerdictConfirmed, Confidence: "medium", Reason: "r"}); return err }},
		{"raised design with fp", func() error { _, err := NewRaised(ts, a, p, e, RaisedData{Kind: ItemDesign, Question: "q?", Fingerprint: f}); return err }},
		{"raised verification without fp", func() error { _, err := NewRaised(ts, a, p, e, RaisedData{Kind: ItemVerification, Question: "q?"}); return err }},
		{"deferred empty reason", func() error { _, err := NewDeferred(ts, a, p, e, f, ""); return err }},
		{"rebaselined missing digest", func() error { _, err := NewRebaselined(ts, a, p, e, RebaselinedData{FromDigest: "x", ToDigest: "", Reason: "r"}); return err }},
		{"resolved empty item", func() error { _, err := NewResolved(ts, a, p, e, ResolvedData{Answer: "a"}); return err }},
		{"bad engine empty", func() error { _, err := NewDeferred(ts, a, p, "", f, "r"); return err }},
	}
	for _, c := range cases {
		if err := c.fn(); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}
```

- [x] **Step 7: Run → PASS**, then tidy the two silencers away, rerun, commit:

```pwsh
go test ./internal/events/ -v
git add internal/events
git commit -m "feat(events): nine typed constructors, validation, canonical encoding"
```

---

## Phase 3 — `internal/config`

### Task 4: Load/Default with unknown-key rejection

**Files:** Create `internal/config/config.go`; Test `internal/config/config_test.go`

- [x] **Step 1: Failing tests**

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, []byte(s), 0o600)
	return p
}

func TestDefaults(t *testing.T) {
	c, err := Load(write(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if c.Engine.Variant != "core" || c.Scan.DeepDefault || c.Scan.ContainerImages ||
		c.Scanners.Checkov || c.Scan.HookExit1 {
		t.Fatalf("bad defaults: %+v", c)
	}
}

func TestUnknownKeyFailsLoud(t *testing.T) {
	_, err := Load(write(t, "scan:\n  deep_default: true\n  nope: 1\n"))
	if err == nil || !contains(err.Error(), "nope") {
		t.Fatalf("want named unknown key, got %v", err)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [x] **Step 2: Run → FAIL**, then implement:

```go
package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Engine struct {
		Variant string `yaml:"variant"`
		Digest  string `yaml:"digest"`
	} `yaml:"engine"`
	Scan struct {
		DeepDefault     bool `yaml:"deep_default"`
		ContainerImages bool `yaml:"container_images"`
		HookExit1       bool `yaml:"hook_exit_1"`
	} `yaml:"scan"`
	Scanners struct {
		Checkov bool `yaml:"checkov"`
	} `yaml:"scanners"`
	Network struct {
		Proxy       string `yaml:"proxy"`
		DBOverrides struct {
			TrivyDB     string `yaml:"trivy_db"`
			TrivyJavaDB string `yaml:"trivy_java_db"`
		} `yaml:"db_overrides"`
	} `yaml:"network"`

	raw map[string]any `yaml:"-"`
}

// StrictKnownKeys decodes twice: once into Config, once generically to detect
// unknown keys (fail loud, cli-spec §5 / artefacts §4).
func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Default(), fmt.Errorf("config.yaml: %w", err)
	}
	switch c.Engine.Variant {
	case "core", "full":
	default:
		return Default(), fmt.Errorf("config.yaml: engine.variant %q (core|full)", c.Engine.Variant)
	}
	return c, nil
}

func Default() Config {
	var c Config
	c.Engine.Variant = "core"
	return c
}
```

Remove the unused `raw` field before committing (it was scaffolding for the double-decode idea; `KnownFields(true)` alone enforces strictness).

- [x] **Step 3: Run → PASS. Commit** `feat(config): strict config.yaml loader`

---

## Phase 4 — `internal/store`

### Task 5: Init/Open, atomic writes

**Files:** Create `internal/store/store.go`, `atomic.go`; Test `internal/store/store_test.go`

- [x] **Step 1: Failing test**

```go
package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitScaffold(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"log", "state", filepath.Join("cache", "advisories"),
		filepath.Join("design", "decisions"), "reports"} {
		if fi, err := os.Stat(filepath.Join(root, ".cavet", d)); err != nil || !fi.IsDir() {
			t.Errorf("missing dir %s", d)
		}
	}
	for _, f := range []string{"config.yaml", ".gitattributes", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(root, ".cavet", f)); err != nil {
			t.Errorf("missing file %s", f)
		}
	}
	if s == nil {
		t.Fatal("nil store")
	}
}

func TestOpenRequiresInit(t *testing.T) {
	if _, err := Open(t.TempDir()); err == nil {
		t.Fatal("expected refusal without init")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	if err := AtomicWrite(p, []byte("{\"a\":1}\n")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "{\"a\":1}\n" {
		t.Fatalf("got %q", b)
	}
	// overwrite stays atomic-shaped
	if err := AtomicWrite(p, []byte("{\"a\":2}\n")); err != nil {
		t.Fatal(err)
	}
}
```

- [x] **Step 2: Run → FAIL**, implement:

```go
// store.go
package store

import (
	"os"
	"path/filepath"
)

type Store struct {
	Root    string // repository root (not .cavet)
	Cavet   string // <Root>/.cavet
}

func cavetDir(root string) string { return filepath.Join(root, ".cavet") }

func Init(root string) (*Store, error) {
	c := cavetDir(root)
	for _, d := range []string{"log", "state", "cache/advisories", "design/decisions", "reports"} {
		if err := os.MkdirAll(filepath.Join(c, d), 0o755); err != nil {
			return nil, err
		}
	}
	files := map[string]string{
		"config.yaml":    defaultConfigYAML,
		".gitattributes": "log/*.jsonl merge=union\n",
		".gitignore":     "state/\ncache/\nreports/\n",
	}
	for name, body := range files {
		p := filepath.Join(c, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				return nil, err
			}
		}
	}
	return &Store{Root: root, Cavet: c}, nil
}

func Open(root string) (*Store, error) {
	s := &Store{Root: root, Cavet: cavetDir(root)}
	if fi, err := os.Stat(filepath.Join(s.Cavet, "config.yaml")); err != nil || fi.IsDir() {
		return nil, ErrNotInitialised
	}
	return s, nil
}

var ErrNotInitialised = errStore("no .cavet/ directory here; run 'cavet init'")

type errStore string

func (e errStore) Error() string { return string(e) }

const defaultConfigYAML = `engine:
  variant: core
scan:
  deep_default: false
  container_images: false
  hook_exit_1: false
scanners:
  checkov: false
network:
  proxy: ""
  db_overrides:
    trivy_db: ""
    trivy_java_db: ""
`
```

```go
// atomic.go
package store

import (
	"os"
	"path/filepath"
)

func AtomicWrite(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
```

- [x] **Step 3: Run → PASS. Commit** `feat(store): scaffold + atomic state writes`

### Task 6: The lock (O_EXCL, stale takeover, cross-platform pid probe)

**Files:** Create `lock.go`, `lock_windows.go`, `lock_unix.go`; Test extend `store_test.go`

- [x] **Step 1: Failing tests**

```go
func TestLockExclusiveAndRelease(t *testing.T) {
	root := t.TempDir()
	s, _ := Init(root)
	rel, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lock(); err == nil {
		t.Fatal("second lock must contend") // same process still holds via O_EXCL
	}
	rel()
	rel2, err := s.Lock()
	if err != nil {
		t.Fatalf("release must free: %v", err)
	}
	rel2()
}

func TestLockStaleTakeover(t *testing.T) {
	root := t.TempDir()
	s, _ := Init(root)
	lockPath := filepath.Join(root, ".cavet", "state", "lock")
	os.WriteFile(lockPath, []byte(`{"pid":999999999,"ts":"2020-01-01T00:00:00Z"}`), 0o600)
	old := time.Now().Add(-2 * time.Minute)
	os.Chtimes(lockPath, old, old)
	rel, err := s.Lock()
	if err != nil {
		t.Fatalf("stale lock must be taken over: %v", err)
	}
	rel()
}
```

- [x] **Step 2: Run → FAIL**, implement `lock.go`:

```go
package store

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const (
	lockWait     = 10 * time.Second
	lockStaleAge = 60 * time.Second
	lockPoll     = 100 * time.Millisecond
)

type lockInfo struct {
	PID int       `json:"pid"`
	TS  time.Time `json:"ts"`
}

func (s *Store) Lock() (func(), error) {
	path := filepath.Join(s.Cavet, "state", "lock")
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			b, _ := json.Marshal(lockInfo{PID: os.Getpid(), TS: time.Now().UTC()})
			f.Write(append(b, '\n'))
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if stale(path) {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			var info lockInfo
			if b, err := os.ReadFile(path); err == nil {
				json.Unmarshal(b, &info)
			}
			return nil, errStore("another cavet process holds the lock (pid " + itoa(info.PID) + ")")
		}
		time.Sleep(lockPoll)
	}
}

func stale(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	if time.Since(fi.ModTime()) > lockStaleAge {
		return true
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var info lockInfo
	if json.Unmarshal(b, &info) != nil {
		return true
	}
	return info.PID != os.Getpid() && !processAlive(info.PID)
}

func itoa(n int) string { return strconv.Itoa(n) } // helper; import strconv instead in final pass
```

`lock_windows.go` — access-denied means the process exists but is protected; treat it
as alive so a live holder's lock is never stolen:

```go
//go:build windows

package store

import (
	"errors"

	"golang.org/x/sys/windows"
)

func processAlive(pid int) bool {
	const SYNCHRONIZE = 0x00100000
	h, err := windows.OpenProcess(SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED) // protected but alive
	}
	windows.CloseHandle(h)
	return true
}
```

`lock_unix.go`:

```go
//go:build !windows

package store

import "syscall"

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
```

(Fix imports in final pass: `strconv` for itoa or inline `strconv.Itoa`; `errors` needed in unix file.)

- [x] **Step 3: Run → PASS. Commit** `feat(store): O_EXCL repo lock with stale takeover`

### Task 7: Append, ReadLog, corruption policy

**Files:** Create `log.go`; Test extend

- [x] **Step 1: Failing tests**

```go
func seedEv(t *testing.T, s *Store) events.Event {
	t.Helper()
	ev, err := events.NewRaised(time.Now().UTC(), events.ActorOperator, events.PhaseDesign,
		"ghcr.io/x@sha256:a", events.RaisedData{Kind: events.ItemDesign, Question: "q?"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestAppendRoundTrip(t *testing.T) {
	root := t.TempDir()
	s, _ := Init(root)
	ev := seedEv(t, s)
	got, err := s.ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != events.Raised {
		t.Fatalf("got %+v", got)
	}
	if !bytes.Equal(events.Canonical(got[0]), events.Canonical(ev)) {
		t.Error("roundtrip changed canonical form")
	}
	if !strings.Contains(filepath.Base(got[0].File), "events-"+time.Now().UTC().Format("2006-01")) {
		t.Errorf("wrong rotation file %s", got[0].File)
	}
}

func TestCorruptLineIsHardError(t *testing.T) {
	root := t.TempDir()
	s, _ := Init(root)
	seedEv(t, s)
	logFile := globOne(t, filepath.Join(root, ".cavet", "log"))
	appendString(t, logFile, "{not json}\n")
	_, err := s.ReadLog()
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Line != 2 {
		t.Fatalf("want ParseError line 2, got %v", err)
	}
}

func TestPartialTailWarnsIgnored(t *testing.T) {
	root := t.TempDir()
	s, _ := Init(root)
	seedEv(t, s)
	logFile := globOne(t, filepath.Join(root, ".cavet", "log"))
	appendString(t, logFile, `{"ts":"2026`) // no newline
	got, err := s.ReadLog()
	if err != nil {
		t.Fatalf("partial tail must not fail: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
}
```

Helpers `globOne`, `appendString`: 5-line test utilities writing into the temp log dir.

- [x] **Step 2: Run → FAIL**, implement `log.go`:

```go
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
)

type ParseError struct {
	File string
	Line int
	Err  error
}

func (p *ParseError) Error() string {
	return fmt.Sprintf("%s:%d: %v (log is source of truth; repair manually)", p.File, p.Line, p.Err)
}

// Enriched carries provenance through replay.
type Enriched struct {
	events.Event
	File string
	Raw  []byte // original line bytes, byte-preserved for unknown kinds
}

func (s *Store) logGlob() ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(s.Cavet, "log", "events-*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches) // lexicographic == chronological
	return matches, nil
}

func (s *Store) Append(e events.Event) error {
	name := "events-" + e.TS.UTC().Format("2006-01") + ".jsonl"
	f, err := os.OpenFile(filepath.Join(s.Cavet, "log", name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	line := append(events.Canonical(e), '\n') // single Write per event (artefacts §7.2)
	_, err = f.Write(line)
	return err
}

func (s *Store) ReadLog() ([]Enriched, error) {
	files, err := s.logGlob()
	if err != nil {
		return nil, err
	}
	var out []Enriched
	for _, file := range files {
		fh, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1024*1024), 16*1024*1024) // SARIF-sized lines never appear here, be safe anyway
		n := 0
		for sc.Scan() {
			n++
			line := sc.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			ev, raw, err := decodeEvent(line)
			if err != nil {
				fh.Close()
				if isPartialTail(sc, err) {
					fmt.Fprintf(os.Stderr, "warning: %s: trailing partial line ignored\n", file)
					break
				}
				return out, &ParseError{File: file, Line: n, Err: err}
			}
			out = append(out, Enriched{Event: ev, File: filepath.Base(file), Raw: raw})
		}
		fh.Close()
	}
	return out, nil
}

func isPartialTail(sc *bufio.Scanner, err error) bool {
	return strings.Contains(err.Error(), "unexpected end of JSON input") && sc.Err() == nil
}

func decodeEvent(line []byte) (events.Event, []byte, error) {
	// strict first pass: schema gates
	var probe struct {
		TS          time.Time     `json:"ts"`
		V           int           `json:"v"`
		Event       events.Kind   `json:"event"`
		Fingerprint string        `json:"fingerprint"`
		Actor       events.Actor  `json:"actor"`
		Phase       events.Phase  `json:"phase"`
		Engine      string        `json:"engine"`
		Data        events.Data   `json:"-"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return events.Event{}, nil, err
	}
	if probe.V > events.SchemaVersion {
		return events.Event{}, nil, fmt.Errorf("log schema v%d newer than binary v%d; upgrade cavet",
			probe.V, events.SchemaVersion)
	}
	ev, err := events.Decode(line) // see Task 7b
	if err != nil {
		return events.Event{}, nil, err
	}
	return ev, line, nil
}
```

- [x] **Step 3: Add `events.Decode`** (parse envelope + dispatch payload by kind, preserving unknown kinds):

```go
// events/decode.go
package events

import "encoding/json"

type decoded struct {
	TS          time.Time   `json:"ts"`
	V           int         `json:"v"`
	Event       Kind        `json:"event"`
	Fingerprint string      `json:"fingerprint"`
	Actor       Actor       `json:"actor"`
	Phase       Phase       `json:"phase"`
	Engine      string      `json:"engine"`
	Data        interface{} `json:"data"` // map for unknown kinds
}

func Decode(line []byte) (Event, error) {
	var d decoded
	if err := json.Unmarshal(line, &d); err != nil {
		return Event{}, err
	}
	e := Event{TS: d.TS, V: d.V, Kind: d.Event, Fingerprint: d.Fingerprint,
		Actor: d.Actor, Phase: d.Phase, Engine: d.Engine}
	raw, err := payloadJSON(d.Event, line)
	if err != nil {
		return e, err
	}
	e.raw = raw
	return e, nil
}

func payloadJSON(k Kind, line []byte) ([]byte, error) {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, err
	}
	typed := knownPayload(k)
	if typed == nil {
		return env.Data, nil // unknown kind: preserved verbatim (artefacts §10)
	}
	v := typed
	return json.Marshal(v) // re-marshal through typed struct → field order stable
}

// knownPayload returns a fresh zero value per kind, nil when unknown.
func knownPayload(k Kind) any {
	switch k {
	case Detected:
		return &DetectedData{}
	case Triaged:
		return &TriagedData{}
	case Surfaced:
		return &SurfacedData{}
	case Remediated:
		return &RemediatedData{}
	case Suppressed:
		return &SuppressedData{}
	case Deferred:
		return &DeferredData{}
	case Raised:
		return &RaisedData{}
	case Resolved:
		return &ResolvedData{}
	case Rebaselined:
		return &RebaselinedData{}
	}
	return nil
}
```

Also add `Payload()` accessor on Event returning the typed payload (switch on Kind, unmarshal `e.raw` lazily and cache) — replay needs values, not just bytes.

- [x] **Step 4: Run → PASS. Commit** `feat(store): append/read log with corruption policy`

### Task 8: Rebuild fold — ordering, duplicates, dangling refs, item ids

**Files:** Create `rebuild.go`, `findings.go` (types shared with CLI), Test extend

- [x] **Step 1: Failing test — determinism under shuffle (the merge=union case)**

```go
func TestRebuildDeterministicUnderShuffle(t *testing.T) {
	build := func() string {
		root := t.TempDir()
		s, _ := Init(root)
		ts := time.Now().UTC()
		mk := func(off time.Duration, q string) events.Event {
			ev, err := events.NewRaised(ts.Add(off), events.ActorAgent, events.PhaseBuild,
				"ghcr.io/x@sha256:a", events.RaisedData{Kind: events.ItemDesign, Question: q})
			if err != nil {
				t.Fatal(err)
			}
			return ev
		}
		// append deliberately out of ts order across two monthly files
		for _, ev := range []events.Event{mk(2*time.Hour, "b?"), mk(1*time.Hour, "a?"), mk(3*time.Hour, "c?")} {
			if err := s.Append(ev); err != nil {
				t.Fatal(err)
			}
		}
		st, err := s.Rebuild()
		if err != nil {
			t.Fatal(err)
		}
		return itemIDsJSON(t, st)
	}
	first := build()
	second := build() // separate trees, same logical order shuffled identically
	if first != second {
		t.Fatalf("non-deterministic replay:\n%s\n%s", first, second)
	}
}
```

Plus: duplicate identical `detected` events collapse to one finding; `triaged` for unknown fingerprint errors with ParseError-style message naming the problem; resolved removes item.

- [x] **Step 2: Run → FAIL**, implement state types + fold:

```go
// findings.go — shapes of artefacts §9
package store

import "time"

type Location struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

type Verdict struct {
	Verdict    string         `json:"verdict"`
	Confidence string         `json:"confidence"`
	Reason     string         `json:"reason"`
	Sources    []events.Source `json:"sources,omitempty"`
	At         time.Time      `json:"at"`
	By         string         `json:"by"`
}

type Finding struct {
	Fingerprint        string     `json:"fingerprint"`
	DisplayID          string     `json:"display_id"`
	RuleKey            string     `json:"rule_key"`
	RuleID             string     `json:"rule_id"`
	OriginatingScanner string     `json:"originating_scanner"`
	AlsoDetectedBy     []string   `json:"also_detected_by,omitempty"`
	Secret             bool       `json:"secret"`
	CollapsedWith      []string   `json:"collapsed_with,omitempty"`
	Severity           string     `json:"severity"`
	Description        string     `json:"description"`
	Locations          []Location `json:"locations"`
	DetectedAt         time.Time  `json:"detected_at"`
	LastSeen           time.Time  `json:"last_seen"`
	Status             string     `json:"status"` // open|confirmed|dismissed|deferred|suppressed
	Verdict            *Verdict   `json:"verdict"`
	InBaseline         bool       `json:"in_baseline"`
}

type Item struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Question   string    `json:"question"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	RaisedAt   time.Time `json:"raised_at"`
	RaisedBy   string    `json:"raised_by"`
}

type Baseline struct {
	EngineDigest string    `json:"engine_digest"`
	CreatedAt    time.Time `json:"created_at"`
	Fingerprints []string  `json:"fingerprints"`
}

type State struct {
	RebuiltAt time.Time  `json:"rebuilt_at"`
	Findings  []*Finding `json:"findings"`
	Items     []Item     `json:"items"`
	Baseline  Baseline   `json:"baseline"`

	findingsByFP map[string]*Finding
	itemsByID    map[string]int // id → index
}
```

```go
// rebuild.go
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
)

func (s *Store) Rebuild() (*State, error) {
	log, err := s.ReadLog()
	if err != nil {
		return nil, err
	}
	sort.SliceStable(log, func(i, j int) bool {
		ti, tj := log[i].TS.UTC(), log[j].TS.UTC()
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		a, b := log[i].Raw, log[j].Raw
		if a == nil {
			a = events.Canonical(log[i].Event)
		}
		if b == nil {
			b = events.Canonical(log[j].Event)
		}
		return bytes.Compare(a, b) < 0
	})

	st := &State{RebuiltAt: time.Now().UTC(),
		findingsByFP: map[string]*Finding{}, itemsByID: map[string]int{}}
	seenCanonical := map[string]bool{}
	var warnings []string

	for _, en := range log {
		key := string(en.Raw)
		if key == "" {
			key = string(events.Canonical(en.Event))
		}
		if en.Kind == events.Detected && seenCanonical[key] {
			continue // duplicate post-merge detection collapses silently (§6.2)
		}
		seenCanonical[key] = true

		switch en.Kind {
		case events.Detected:
			d, ok := en.Payload().(events.DetectedData)
			if !ok {
				return nil, &ParseError{File: en.File, Line: -1, Err: fmt.Errorf("detected payload mismatch")}
			}
			if prev, exists := st.findingsByFP[en.Fingerprint]; exists {
				prev.Locations = appendUniqueLoc(prev.Locations, Location{d.Path, d.Line})
				prev.LastSeen = en.TS
				continue
			}
			f := &Finding{
				Fingerprint: en.Fingerprint, RuleKey: ruleKeyOf(d.Rule), RuleID: d.Rule,
				OriginatingScanner: d.Scanner, AlsoDetectedBy: d.AlsoDetectedBy,
				Secret: d.Scanner == "gitleaks" || isTrivySecretRule(d.Rule),
				Severity: string(d.Severity), Description: d.Description,
				Locations:  []Location{{Path: d.Path, Line: d.Line}},
				DetectedAt: en.TS, LastSeen: en.TS, Status: "open",
			}
			st.Findings = append(st.Findings, f)
			st.findingsByFP[f.Fingerprint] = f

		case events.Triaged:
			f, ok := st.findingsByFP[en.Fingerprint]
			if !ok {
				return nil, &ParseError{File: en.File, Line: -1,
					Err: fmt.Errorf("triaged references unknown fingerprint %s", short(en.Fingerprint))}
			}
			d := en.Payload().(events.TriagedData)
			f.Verdict = &Verdict{Verdict: string(d.Verdict), Confidence: string(d.Confidence),
				Reason: d.Reason, Sources: d.Sources, At: en.TS, By: string(en.Actor)}
			f.Status = map[string]string{
				string(events.VerdictConfirmed): "confirmed",
				string(events.VerdictDismissed): "dismissed",
			}[string(d.Verdict)]
			if f.Status == "confirmed" {
				f.Status = "open" // confirmed findings remain actionable; status tracks lifecycle below
			}

		case events.Suppressed:
			if err := setStatus(st, en, "suppressed"); err != nil {
				return nil, err
			}
		case events.Deferred:
			if err := setStatus(st, en, "deferred"); err != nil {
				return nil, err
			}
		case events.Remediated:
			f, ok := st.findingsByFP[en.Fingerprint]
			if !ok {
				return nil, &ParseError{File: en.File, Line: -1,
					Err: fmt.Errorf("remediated references unknown fingerprint")}
			}
			removeFinding(st, f)

		case events.Raised:
			d := en.Payload().(events.RaisedData)
			sum := sha256.Sum256(events.Canonical(en.Event))
			id := "it-" + hex.EncodeToString(sum[:])[:8]
			if _, dup := st.itemsByID[id]; dup {
				id += "-2" // content-derived ids can only collide on identical content; suffix keeps both visible
			}
			st.Items = append(st.Items, Item{ID: id, Kind: string(d.Kind), Question: d.Question,
				Fingerprint: d.Fingerprint, RaisedAt: en.TS, RaisedBy: string(en.Actor)})
			st.itemsByID[id] = len(st.Items) - 1

		case events.Resolved:
			d := en.Payload().(events.ResolvedData)
			idx, ok := st.itemsByID[d.Item]
			if !ok {
				return nil, &ParseError{File: en.File, Line: -1,
					Err: fmt.Errorf("resolved references unknown item %q", d.Item)}
			}
			removeItem(st, idx)

		case events.Rebaselined:
			// baseline fingerprints arrive from the scan that rebaseline ran;
			// replay reconstructs membership from subsequent baseline.json write — see Task 8b note
		case events.Surfaced:
			// presentation is history, not state (§6.2)
		default:
			warnings = append(warnings, "unknown event kind "+string(en.Kind)+" preserved verbatim, excluded from fold")
		}
	}
	if len(warnings) > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d unknown-kind events preserved\n", len(warnings))
	}
	assignDisplayIDs(st.Findings)
	return st, s.writeState(st)
}
```

Notes to resolve while implementing (they are decisions, not gaps):
- `resolved` correlation: the `resolved` payload carries `item`, the id of the open item being closed (decided 2026-08-25; artefacts §14.7 supersedes the earlier answer-prefix draft). `cavet resolve <item-id>` validates the id against open items and records it in the event.
- Confirmed findings take `status:"confirmed"` with a verdict block, per the artefacts §9.1 enum (`open|confirmed|dismissed|deferred|suppressed`). Status tracks lifecycle; the verdict block records the judgement.
- Canonical-line dedup applies to every event kind, not only `detected`: after a `merge=union` merge any event type can appear twice, and identical lines collapse silently (artefacts §6.2).

`writeState` marshals State (minus private maps via custom MarshalJSON omitting them), writes `findings.json`+`items.json`+`baseline.json` atomically.

- [x] **Step 3: Run → PASS. Commit** `feat(store): deterministic replay fold with display ids and item ids`

---

## Phase 5 — `internal/output`

### Task 9: Result renderer, golden-tested against spec §4.1

**Files:** Create `internal/output/render.go`; Test `render_test.go` + golden `testdata/golden/reference.md`

- [x] **Step 1: Golden file** — exact contents of spec §4.1 reference block (header line through `next:` hints), saved as `testdata/golden/reference.md`.

- [x] **Step 2: Failing test**

```go
package output

import (
	"os"
	"testing"
)

func TestGoldenReference(t *testing.T) {
	view := ScanView{
		Scope: "staged", Scanners: []string{"gitleaks", "trivy"}, Phase: "build",
		EngineShort: "cavet-engine@sha256:4f2a",
		Counts: Counts{Confirmed: 2, High: 1, Medium: 1, Dismissed: 14, Baseline: 347},
		Findings: []FindingView{
			{ID: "a3f9c2", Sev: "high", Rule: "py.sql-injection", Loc: "api/users.py:88", Desc: "user input concatenated into query"},
			{ID: "7b1e04", Sev: "medium", Rule: "generic.weak-hash", Loc: "auth/tokens.py:23", Desc: "MD5 used for token derivation"},
		},
		Hints: []string{"cavet finding a3f9c2 --full", "cavet log --fingerprint 7b1e04"},
	}
	assertGolden(t, RenderResult(view), "golden/reference.md")
}

func TestEmptyStates(t *testing.T) {
	if got := RenderResult(ScanView{Scanners: []string{"gitleaks", "trivy"}}); !contains(got, "0 new findings") {
		t.Fatalf("empty state must be explicit: %q", got)
	}
}
```

(`assertGolden` compares against file; `-update` flag regenerates goldens.)

- [x] **Step 3: Run → FAIL**, implement renderer exactly per cli-spec §9 rules (fixed columns, sort sev→path→line, truncate desc 60 chars, ≤3 hints). Straightforward string building — ~90 lines.

- [x] **Step 4: Run → PASS. Commit** `feat(output): normative result rendering with golden tests`

---

## Phase 6 — `internal/projection`

### Task 10: SARIF parsing, lazy rule resolution, severity maps

**Files:** Create `sarif.go`, `severity.go`; Test `sarif_test.go` using spike fixtures

- [x] **Step 1: Failing tests against real fixtures**

```go
func TestParseOpengrepFixture(t *testing.T) {
	b, _ := os.ReadFile("../../finding/testdata/opengrep.sarif")
	fs, warns, err := Parse("opengrep", b)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	if len(fs) == 0 {
		t.Fatal("fixture has planted findings; got none")
	}
	for _, f := range fs {
		if f.Severity == "" || f.Path == "" || f.RuleKey == "" {
			t.Fatalf("incomplete finding %+v", f)
		}
	}
}

func TestSeverityMaps(t *testing.T) {
	cases := map[string]struct {
		in, want string
	}{
		"trivy critical": {"CRITICAL", "critical"},
		"trivy unknown":  {"UNKNOWN", "info"},
		"opengrep error": {"ERROR", "high"},
		"opengrep info":  {"INFO", "info"},
		"gitleaks none":  {"", "high"},
	}
	for name, c := range cases {
		if got := NormalizeSeverity(scannerOf(name), c.in); got != c.want {
			t.Errorf("%s: got %q want %q", name, got, c.want)
		}
	}
}
```

- [x] **Step 2: Run → FAIL**, implement `sarif.go` structs per cli-spec §9 parsing rules (results[] iteration, memoised ruleIndex→metadata, malformed result drops row with warning) and `severity.go` mapping tables verbatim from cli-spec §7.

- [x] **Step 3: Run → PASS. Commit** `feat(projection): SARIF parse with lazy rule resolution and severity maps`

### Task 11: Merge + secret collapse

**Files:** Create `merge.go`; Test `merge_test.go` with hand-built pair

- [x] **Step 1: Hand-built fixture pair** (spike §7 consequence — committed as `testdata/secrets/a.sarif`, `b.sarif`): two minimal SARIF docs reporting the same synthetic high-entropy span at `config.py:9` under rule ids `generic-api-key` (gitleaks) and `stripe-secret-token` (trivy).

- [x] **Step 2: Failing test**: parsing both + merging yields ONE finding whose `OriginatingScanner=="gitleaks"`, `CollapsedWith==["stripe-secret-token"]`, single fingerprint from `fingerprint.Secret`.

- [x] **Step 3: Implement `merge.go`**: group by `Secret(span,path)` for secret-category findings (gitleaks: all; trivy: rules containing "secret"/"token" per Trivy's secret-scanner id conventions — encode the predicate explicitly), else group by `Of(RuleKey(...), Normalise(...))`; multi-location dedup.

- [x] **Step 4: PASS, commit** `feat(projection): cross-scanner merge with pre-fingerprint secret collapse`

---

## Phase 7 — Engine image

### Task 12: Dockerfile, entrypoint, healthcheck, curation, licence notice

**Files:** Create everything under `engine/` per engine-spec §§2–7

- [x] **Step 1: `engine/Dockerfile`** — transcribe engine-spec §3 stage skeleton verbatim into a working file: base (locales, git, ca-certificates, UTF-8 ENV), scanners stage (checksum-verified pinned downloads for opengrep 1.27.1, gitleaks 8.30.1, trivy 0.74.0, checkov pip-pin), rules stage (clone pinned SHA, run `curate-rules.sh`, count assertion `[1700,2100]`), trivy-data-core/full stages (`--download-db-only`, policy bundle bake, java-db only in full), two finals copying entrypoint/healthcheck/LICENSES.md.

- [x] **Step 2: `engine/curate-rules.sh`** — mechanical filter per engine-spec §4.4: language dirs only, exclude `*.test.yaml`/`*.fixture.*`/dotfiles/pre-commit configs, then:

```sh
COUNT=$(find /opt/opengrep-rules -name '*.yaml' | wc -l)
if [ "$COUNT" -lt 1700 ] || [ "$COUNT" -gt 2100 ]; then
  echo "rule count $COUNT outside [1700,2100]" >&2; exit 1
fi
```

- [x] **Step 3: `entrypoint.sh` + `healthcheck`** — transcribe engine-spec §6.1/§6.2 scripts verbatim (safe.directory, /scan+/reports mkdir; five healthcheck assertions).

- [x] **Step 4: `LICENSES.md`** — Commons Clause text verbatim from spike §1 quote + attributions per engine-spec §7.

- [x] **Step 5: Build + acceptance gates locally**

```pwsh
docker buildx build --platform linux/amd64 -t cavet-engine:dev -f engine/Dockerfile engine/
docker run --rm cavet-engine:dev cavet-healthcheck   # exit 0
```

Offline gate (§8.1.3): disconnect network (`--network none`), mount fixture repo, run staged trivy invocation with mandatory flags — expect SARIF with planted findings.

- [x] **Step 6: Commit** `feat(engine): digest-pinned multi-stage image with curated rules and offline gates`

---

## Phase 8 — `internal/engineclient` + scan pipeline

### Task 13: Container lifecycle + exec

**Files:** Create `engineclient/client.go`, `exec.go`, `paths.go`; Test with mocked-free integration guard (skip when no Docker: `t.Skip` on daemon ping failure)

- [x] **Step 1: Tests** (integration-tagged): container name derivation stable (`cavet-<12hex>` of abs root); EnsureRunning starts and health-probes; ExecCapture returns stdout; CopyOut retrieves `/reports/x.sarif`; PathTranslate bidirectional incl. Windows drive case.

- [x] **Step 2: Implement** per cli-spec §10: SDK client from env (`client.NewClientWithOpts(client.FromEnv)`), create-with-bind-mount (`/workspace`, network disabled unless proxy configured), start, probe `["/usr/local/bin/cavet-healthcheck"]` 30s cold timeout; wrong-digest → hard stop with rebaseline instruction; exec plumbing `ExecCreate+AttachOutput`; `--user uid:gid` on linux hosts; `\\?\` long-path handling for temp staging.

- [x] **Step 3: Integration run against dev image → PASS. Commit** `feat(engineclient): lifecycle, exec, copy-out, path translation`

### Task 14: Scope resolution + scan pipeline + delta

**Files:** Create `internal/scan/scope.go`, `pipeline.go`, `delta.go`; Test `*_test.go` with fake engineclient (interface seam introduced here: `type runner interface { Exec(...) ; CopyOut(...) }` — one producer, justified seam)

- [x] **Step 1: Failing unit tests with fake runner**:
  - staged scope: `git diff --cached --name-only -z` then `git checkout-index --prefix=/scan/1/ --stdin` invoked with staged list; empty index → `nothing staged` result object, no scanner exec.
  - tier selection table (cli-spec §6) incl. config.deep_default.
  - delta fold (cli-spec §8.3): unseen→detected+insert-open; known→last_seen refresh only; remediation requires originating-scanner-ran AND all locations in-scope AND absent; regression reopen emits fresh detected.
  - surfaced emission with `--context` value; state rewritten atomically; latest.sarif merged doc.

- [x] **Step 2: Implement** — orchestrate: resolve scope → ensure container → stage target → invoke scanner contracts verbatim from cli-spec §7 (flags included) → CopyOut SARIFs → projection.Parse+Merge → delta fold under store lock (exec outside lock per cli-spec §14) → write reports/state → return ScanView to caller.

- [x] **Step 3: Unit PASS. Commit** `feat(scan): tiers, staged staging via checkout-index, delta fold with remediation gating`

---

## Phase 9 — CLI surface

### Tasks 15–18: cobra wiring, grouped

**Files:** Create `internal/cli/root.go`, `init.go`, `scan.go`, `finding.go`, `triage.go`, `lifecycle.go` (suppress/defer/raise/resolve), `items.go`, `logdebt.go`, `rebuild.go`, `engine.go`, `hook.go`; modify `cmd/cavet/main.go`

Each command task follows the same loop: wire flags exactly as cli-spec §5 table; behaviour calls into the packages above; verify with built binary against a scratch repo; commit.

- [x] **Task 15: root + init + posture view** — root prints posture (exit 0 always); init runs scaffold→pull→start→full baseline scan→detected events→baseline.json→exact two-line output (cli-spec §5), with stderr progress during pull/start/baseline (cli-spec §5 step 5, deviation §16.8); refuses re-init; `--hooks` delegates to Task 17's installer.
- [x] **Task 16: scan + finding + triage/suppress/defer** — scan flags `--staged|--diff|--full|--deep|--phase|--context`, exit codes 0/1/2 per §4.1; triage requires `--reason` AND `--confidence` (no defaults, cli-spec §16.1); suppress/defer require reasons; all take the lock.
- [x] **Task 17: raise/resolve/items/log/debt/rebuild/rebaseline** — raise prints `it-xxxxxxxx`; resolve correlates item id (§ Task 8 note); rebaseline interactive-confirm unless `--yes`; rebuild prints counts line.
- [x] **Task 18: engine group + hook installation** — status/start/stop/pull/shell (shell TTY-gated before Docker contact); `init --hooks` sets `core.hooksPath=.cavet/hooks`, writes POSIX shim per cli-spec §13 + Windows `.cmd` fallback calling the exe directly.

Each ends with: `go build ./... && ./cavet <cmd> --help` shows exact flags; commit message `feat(cli): <group>`.

---

## Phase 10 — Lookup + describe

### Task 19: Five adapters + cache + renderer

**Files:** Create `internal/lookup/*` per file-structure map; Test recorded-HTTP fixtures (offline CI)

- [x] **Step 1: Cache round-trip test** — wrapper fields (identifier/fetched_at/ttl_hours=168/payload), stale+offline serves stale marker, torn file deleted-refetched (artefacts §11).
- [x] **Step 2: OSV adapter complete** (querybatch POST, /v1/vulns/{id}); KEV whole-feed daily cache; EPSS GET; NVD optional `NVD_API_KEY`; registry dispatch on purl type over npm/PyPI/crates/go-proxy JSON APIs. Shared helpers only (timeout 10s, one retry on 429/5xx after 1s) — no shared interface (spec §5.3).
- [x] **Step 3: Renderer** — compact markdown table: severity, affected range, fixed version, KEV flag, EPSS, summary, URL; degraded cells render explicit `not available`; rule-ids resolve from engine-extracted catalogue (`cache/advisories/rules-<digest8>.json` produced by `engine pull`).
- [x] **Step 4: PASS, commit** `feat(lookup): five thin adapters, weekly cache, degraded-cell rendering`

### Task 20: describe --json

**Files:** Create `internal/describe/describe.go` + CLI wiring

- [x] Emit cli-spec §12 schema verbatim; `--skills-dir` overrides recommended_path prefix; refuses without `--json`; additive-only versioning comment at top of file. Golden-test the emitted JSON structure. Commit `feat(describe): machine contract emitter`.

---

## Phase 11 — End-to-end smoke + polish

### Task 21: Smoke script

**Files:** Create `scripts/smoke.ps1`

- [x] Script: builds binary; copies `internal/finding/testdata/fixture/` to temp repo; `cavet init` (requires dev engine image); asserts baseline count ≥ planted findings; stages `api/users.py` change; `cavet scan --staged` exits 1 with secret finding present; `cavet triage <id> --dismiss --reason "fixture" --confidence high` succeeds; `cavet log --fingerprint <fp>` shows detected+triaged; `cavet items/raise/resolve` round-trip; second clean staged scan exits 0 with `0 new findings`; verifies `reports/latest.sarif` exists. Run green locally, wire into CI behind Docker-availability check. Commit `test: end-to-end smoke script`.

### Task 22: Installers + README

**Files:** Create `installers/{claude-code,codex,opencode,pi,hermes}.ps1` (+ `.sh` mirrors); Modify `README.md`

- [ ] Each installer: copy six skill dirs → harness skills path (table of paths per harness documented in-file), translate `subagents/cavet-security.md` into harness format, append instruction snippet to agent instruction file (idempotently — check-before-append). Claude Code installer implemented first as reference; remaining four follow its structure with harness-specific targets. Harness set (decided 2026-08-25, usage-ranked via OpenRouter coding rankings): Claude Code, Codex, Hermes, pi, OpenCode — the pi installer also covers the omp family.
- [ ] README: replace "nothing built" status block; add quick-start (install → `cavet init` → skills snippet); keep licence section unchanged. Commit `feat(installers): five harness installers; readme quick-start`.

### Task 23: Tag release

- [ ] `engine/build.ps1` publishes multi-arch manifest, records digest into `engine/digest.txt`; GitHub Release with binaries (windows/amd64, linux/amd64+arm64, darwin/amd64+arm64) via goreleaser config added in this task. Commit `chore: release engineering, v0.1.0 tag`.

---

## Spec coverage matrix (self-review)

| Annex section | Task(s) |
|---|---|
| artefacts §1 layout/scaffold | 5 |
| artefacts §2 event schema/envelope | 3 |
| artefacts §4 config schema (incl. hook_exit_1 fix) | 4 |
| artefacts §5 fingerprint algorithm | 2, 11 |
| artefacts §6 replay/ordering/rebaseline/last_seen gap | 8, 17 |
| artefacts §7 concurrency/atomicity | 5, 6 |
| artefacts §8 corruption policy | 7 |
| artefacts §9 state schemas | 8 |
| artefacts §10 evolution (unknown kinds, v-gate) | 7 |
| artefacts §11 advisory cache | 19 |
| cli §4 global behaviours | 15–17 |
| cli §5 all 16 commands | 15–18, 20 |
| cli §6–8 scan tiers/staging/scanner contracts/delta | 14 |
| cli §9 projection grammar | 9 |
| cli §10 engine client | 13 |
| cli §11 lookup | 19 |
| cli §12 describe | 20 |
| cli §13 hooks | 18 |
| engine §§2–9 image/build/gates | 12, 23 |
| skills component | already drafted; installers wire them (22) |

## Known deferrals (deliberate, from spec)

- Evaluation fixtures across models/harnesses — spec §13.2 says defer until real use.
- `opengrep lsp` persistent server amortisation — spike §2 says not v0.1.
- Agent Plugins 1.0 manifest — spec §2.2.
