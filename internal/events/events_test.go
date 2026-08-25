package events

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func fp64() string {
	return "a3f9c2e41b77d0c8a3f9c2e41b77d0c8a3f9c2e41b77d0c8a3f9c2e41b77d0c8"
}

const testEngine = "ghcr.io/x@sha256:a"

func TestTriagedCanonicalShape(t *testing.T) {
	ts := time.Date(2026, 8, 17, 9, 14, 22, 0, time.UTC)
	ev, err := NewTriaged(ts, ActorAgent, PhaseBuild, testEngine, fp64(), TriagedData{
		Verdict: VerdictDismissed, Confidence: ConfidenceHigh,
		Reason: "test fixture", Sources: []Source{{ID: "GHSA-x", URL: "https://g"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(Canonical(ev), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ts", "v", "event", "fingerprint", "actor", "phase", "engine", "data"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	if string(m["event"]) != `"triaged"` || string(m["v"]) != "1" {
		t.Errorf("bad envelope: %s", Canonical(ev))
	}
	if string(m["ts"]) != `"2026-08-17T09:14:22Z"` {
		t.Errorf("ts must be RFC3339 UTC, got %s", m["ts"])
	}
}

func TestCanonicalIsDeterministic(t *testing.T) {
	ts := time.Date(2026, 8, 17, 9, 14, 22, 0, time.UTC)
	mk := func() Event {
		ev, err := NewSuppressed(ts, ActorOperator, PhaseBuild, testEngine, fp64(), "fixture key")
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	if !bytes.Equal(Canonical(mk()), Canonical(mk())) {
		t.Fatal("canonical form must be byte-deterministic")
	}
}

func TestRaisedEnvelopeOmitsFingerprint(t *testing.T) {
	raised, err := NewRaised(time.Now().UTC(), ActorAgent, PhaseDesign, testEngine,
		RaisedData{Kind: ItemVerification, Question: "q?", Fingerprint: fp64()})
	if err != nil {
		t.Fatal(err)
	}
	if raised.Fingerprint != "" {
		t.Fatal("raised envelope must not carry the fingerprint (it travels in data)")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(Canonical(raised), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["fingerprint"]; ok {
		t.Fatal("raised canonical must omit the fingerprint key")
	}
	if !bytes.Contains(m["data"], []byte(fp64())) {
		t.Fatal("verification fingerprint must travel in data")
	}
}

func TestConstructorRejections(t *testing.T) {
	ts := time.Now()
	a := ActorAgent
	p := PhaseBuild
	e := testEngine
	f := fp64()
	cases := []struct {
		name string
		fn   func() error
	}{
		{"triaged empty reason", func() error {
			_, err := NewTriaged(ts, a, p, e, f, TriagedData{Verdict: VerdictConfirmed, Confidence: ConfidenceLow})
			return err
		}},
		{"triaged bad confidence", func() error {
			_, err := NewTriaged(ts, a, p, e, f, TriagedData{Verdict: VerdictConfirmed, Confidence: "medium", Reason: "r"})
			return err
		}},
		{"detected missing fingerprint", func() error {
			_, err := NewDetected(ts, a, p, e, "", DetectedData{Rule: "r", Severity: SevHigh, Path: "x.py", Line: 1, Scanner: "opengrep"})
			return err
		}},
		{"detected bad line", func() error {
			_, err := NewDetected(ts, a, p, e, f, DetectedData{Rule: "r", Severity: SevHigh, Path: "x.py", Line: 0, Scanner: "opengrep"})
			return err
		}},
		{"surfaced bad context", func() error {
			_, err := NewSurfaced(ts, a, p, e, f, SurfacedData{Context: "somewhere"})
			return err
		}},
		{"raised design with fingerprint", func() error {
			_, err := NewRaised(ts, a, p, e, RaisedData{Kind: ItemDesign, Question: "q?", Fingerprint: f})
			return err
		}},
		{"raised verification without fingerprint", func() error {
			_, err := NewRaised(ts, a, p, e, RaisedData{Kind: ItemVerification, Question: "q?"})
			return err
		}},
		{"deferred empty reason", func() error {
			_, err := NewDeferred(ts, a, p, e, f, "")
			return err
		}},
		{"rebaselined missing digest", func() error {
			_, err := NewRebaselined(ts, a, p, e, RebaselinedData{FromDigest: "x", ToDigest: "", Reason: "r"})
			return err
		}},
		{"resolved empty item", func() error {
			_, err := NewResolved(ts, a, p, e, ResolvedData{Answer: "a"})
			return err
		}},
		{"resolved malformed item", func() error {
			_, err := NewResolved(ts, a, p, e, ResolvedData{Item: "it-zzz", Answer: "a"})
			return err
		}},
		{"bad engine empty", func() error {
			_, err := NewDeferred(ts, a, p, "", f, "r")
			return err
		}},
		{"bad actor", func() error {
			_, err := NewDeferred(ts, "someone", p, e, f, "r")
			return err
		}},
		{"bad phase", func() error {
			_, err := NewDeferred(ts, a, "lunch", e, f, "r")
			return err
		}},
	}
	for _, c := range cases {
		if err := c.fn(); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestValidConstructors(t *testing.T) {
	ts := time.Now()
	e := testEngine
	f := fp64()
	if _, err := NewDetected(ts, ActorAgent, PhaseBuild, e, f,
		DetectedData{Rule: "r", Severity: SevHigh, Path: "x.py", Line: 3, Scanner: "gitleaks"}); err != nil {
		t.Errorf("detected: %v", err)
	}
	if _, err := NewRaised(ts, ActorOperator, PhaseDesign, e,
		RaisedData{Kind: ItemDesign, Question: "q?"}); err != nil {
		t.Errorf("raised design: %v", err)
	}
	if _, err := NewResolved(ts, ActorOperator, PhaseBuild, e,
		ResolvedData{Item: "it-b7d21c0f", Answer: "yes"}); err != nil {
		t.Errorf("resolved: %v", err)
	}
	if _, err := NewRebaselined(ts, ActorOperator, PhaseBuild, e,
		RebaselinedData{FromDigest: "sha256:a", ToDigest: "sha256:b", Reason: "bump"}); err != nil {
		t.Errorf("rebaselined: %v", err)
	}
}
