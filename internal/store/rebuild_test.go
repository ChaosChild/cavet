package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
)

func fpA() string { return strings.Repeat("a1", 32) }
func fpB() string { return strings.Repeat("b2", 32) }

var baseTS = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func itemID(ev events.Event) string {
	sum := sha256.Sum256(events.Canonical(ev))
	return "it-" + hex.EncodeToString(sum[:])[:8]
}

func TestRebuildDeterministicUnderShuffle(t *testing.T) {
	build := func(order []time.Duration) string {
		t.Helper()
		root := t.TempDir()
		s, err := Init(root)
		if err != nil {
			t.Fatal(err)
		}
		questions := map[time.Duration]string{
			time.Hour:       "a?",
			2 * time.Hour:   "b?",
			3 * time.Hour:   "c?",
		}
		for _, off := range order {
			ev, err := events.NewRaised(baseTS.Add(off), events.ActorAgent, events.PhaseBuild,
				testEngine, events.RaisedData{Kind: events.ItemDesign, Question: questions[off]})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Append(ev); err != nil {
				t.Fatal(err)
			}
		}
		st, err := s.Rebuild()
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(st.Items)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// Same events, different physical append orders (the merge=union case):
	// replay must impose one total order regardless.
	first := build([]time.Duration{2 * time.Hour, time.Hour, 3 * time.Hour})
	second := build([]time.Duration{3 * time.Hour, time.Hour, 2 * time.Hour})
	if first != second {
		t.Fatalf("non-deterministic replay:\n%s\n%s", first, second)
	}
}

func TestRebuildDuplicateAndMultiLocation(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(path string, line int, off time.Duration) events.Event {
		ev, err := events.NewDetected(baseTS.Add(off), events.ActorAgent, events.PhaseBuild,
			testEngine, fpA(), events.DetectedData{
				Rule: "py.sql-injection", Severity: events.SevHigh,
				Path: path, Line: line, Scanner: "opengrep",
				Description: "user input into query",
			})
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	ev1 := mk("api/users.py", 88, 0)
	for _, ev := range []events.Event{ev1, ev1, mk("api/orders.py", 12, time.Hour)} {
		if err := s.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	st, err := s.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Findings) != 1 {
		t.Fatalf("duplicates must collapse, got %d findings", len(st.Findings))
	}
	f := st.Findings[0]
	if len(f.Locations) != 2 {
		t.Fatalf("want 2 locations, got %+v", f.Locations)
	}
	if !f.DetectedAt.Equal(baseTS) || !f.LastSeen.Equal(baseTS.Add(time.Hour)) {
		t.Fatalf("timestamps wrong: detected %v last_seen %v", f.DetectedAt, f.LastSeen)
	}
	if f.DisplayID == "" {
		t.Fatal("display id must be assigned")
	}
}

func TestRebuildLifecycleFold(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	detected, err := events.NewDetected(baseTS, events.ActorAgent, events.PhaseBuild,
		testEngine, fpA(), events.DetectedData{
			Rule: "generic-api-key", Severity: events.SevHigh,
			Path: "config.py", Line: 9, Scanner: "gitleaks",
		})
	if err != nil {
		t.Fatal(err)
	}
	triaged, err := events.NewTriaged(baseTS.Add(time.Minute), events.ActorAgent, events.PhaseBuild,
		testEngine, fpA(), events.TriagedData{
			Verdict: events.VerdictDismissed, Confidence: events.ConfidenceHigh, Reason: "fixture",
		})
	if err != nil {
		t.Fatal(err)
	}
	raised, err := events.NewRaised(baseTS.Add(2*time.Minute), events.ActorAgent, events.PhaseBuild,
		testEngine, events.RaisedData{Kind: events.ItemVerification, Question: "q?", Fingerprint: fpA()})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := events.NewResolved(baseTS.Add(3*time.Minute), events.ActorOperator, events.PhaseBuild,
		testEngine, events.ResolvedData{Item: itemID(raised), Answer: "yes"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []events.Event{detected, triaged, raised, resolved} {
		if err := s.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	st, err := s.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(st.Findings))
	}
	if st.Findings[0].Status != "dismissed" || st.Findings[0].Verdict == nil {
		t.Fatalf("triage not folded: %+v", st.Findings[0])
	}
	if len(st.Items) != 0 {
		t.Fatalf("resolved must remove the item, got %+v", st.Items)
	}
}

func TestRebuildRemediatedRemovesFinding(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	detected, err := events.NewDetected(baseTS, events.ActorAgent, events.PhaseBuild,
		testEngine, fpB(), events.DetectedData{
			Rule: "generic.weak-hash", Severity: events.SevMedium,
			Path: "auth/tokens.py", Line: 23, Scanner: "opengrep",
		})
	if err != nil {
		t.Fatal(err)
	}
	remediated, err := events.NewRemediated(baseTS.Add(time.Hour), events.ActorAgent, events.PhaseBuild,
		testEngine, fpB(), "finding absent from covering scan")
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []events.Event{detected, remediated} {
		if err := s.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	st, err := s.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Findings) != 0 {
		t.Fatalf("remediated must remove the finding, got %+v", st.Findings)
	}
}

func TestRebuildDanglingRefsFailLoud(t *testing.T) {
	cases := map[string]events.Event{}
	triaged, _ := events.NewTriaged(baseTS, events.ActorAgent, events.PhaseBuild,
		testEngine, fpB(), events.TriagedData{
			Verdict: events.VerdictConfirmed, Confidence: events.ConfidenceLow, Reason: "r",
		})
	cases["triaged without detection"] = triaged
	resolved, _ := events.NewResolved(baseTS, events.ActorOperator, events.PhaseBuild,
		testEngine, events.ResolvedData{Item: "it-00000000", Answer: "a"})
	cases["resolved without raise"] = resolved

	for name, ev := range cases {
		root := t.TempDir()
		s, err := Init(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Append(ev); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Rebuild(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestRebuildPreservesBaseline(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	baseline := []byte(`{"engine_digest":"ghcr.io/x@sha256:a","created_at":"2026-08-17T09:20:00Z","fingerprints":["` + fpA() + `"]}` + "\n")
	if err := AtomicWrite(filepath.Join(root, ".cavet", "state", "baseline.json"), baseline); err != nil {
		t.Fatal(err)
	}
	ev, err := events.NewRaised(baseTS, events.ActorOperator, events.PhaseDesign,
		testEngine, events.RaisedData{Kind: events.ItemDesign, Question: "q?"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ev); err != nil {
		t.Fatal(err)
	}
	st, err := s.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	if st.Baseline.EngineDigest != "ghcr.io/x@sha256:a" || len(st.Baseline.Fingerprints) != 1 {
		t.Fatalf("baseline not preserved: %+v", st.Baseline)
	}
	for _, f := range []string{"findings.json", "items.json"} {
		if _, err := os.Stat(filepath.Join(root, ".cavet", "state", f)); err != nil {
			t.Errorf("state file %s missing: %v", f, err)
		}
	}
}

func TestRebuildDisplayIDCollisionExtends(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	// Two fingerprints sharing a 6-hex prefix force longer display ids.
	fp1 := "abcdef0001" + strings.Repeat("0", 54)
	fp2 := "abcdef0002" + strings.Repeat("0", 54)
	for i, fp := range []string{fp1, fp2} {
		ev, err := events.NewDetected(baseTS.Add(time.Duration(i)*time.Minute), events.ActorAgent,
			events.PhaseBuild, testEngine, fp, events.DetectedData{
				Rule: "r", Severity: events.SevLow, Path: "x.py", Line: i + 1, Scanner: "opengrep",
			})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	st, err := s.Rebuild()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(st.Findings))
	}
	a, b := st.Findings[0].DisplayID, st.Findings[1].DisplayID
	if a == b || len(a) < 7 || len(b) < 7 {
		t.Fatalf("colliding prefixes must extend: %q vs %q", a, b)
	}
}
