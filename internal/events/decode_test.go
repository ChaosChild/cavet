package events

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestDecodeRoundTrip(t *testing.T) {
	ts := time.Date(2026, 8, 17, 9, 14, 22, 0, time.UTC)
	ev, err := NewTriaged(ts, ActorAgent, PhaseBuild, testEngine, fp64(), TriagedData{
		Verdict: VerdictConfirmed, Confidence: ConfidenceLow, Reason: "reachable",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(Canonical(ev))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Canonical(got), Canonical(ev)) {
		t.Fatalf("decode changed canonical form:\n%s\n%s", Canonical(got), Canonical(ev))
	}
	d, ok := got.Payload().(TriagedData)
	if !ok || d.Reason != "reachable" || d.Verdict != VerdictConfirmed {
		t.Fatalf("payload mismatch: %+v", got.Payload())
	}
}

func TestDecodeRejectsNewerSchema(t *testing.T) {
	line := `{"ts":"2026-08-17T09:14:22Z","v":2,"event":"triaged","actor":"agent","phase":"build","engine":"x","data":{}}`
	_, err := Decode([]byte(line))
	if err == nil || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("want upgrade error, got %v", err)
	}
}

func TestDecodeRejectsBadEnvelope(t *testing.T) {
	cases := map[string]string{
		"bad actor": `{"ts":"2026-08-17T09:14:22Z","v":1,"event":"deferred","fingerprint":"` + fp64() + `","actor":"someone","phase":"build","engine":"x","data":{"reason":"r"}}`,
		"bad phase": `{"ts":"2026-08-17T09:14:22Z","v":1,"event":"deferred","fingerprint":"` + fp64() + `","actor":"agent","phase":"lunch","engine":"x","data":{"reason":"r"}}`,
		"no engine": `{"ts":"2026-08-17T09:14:22Z","v":1,"event":"deferred","fingerprint":"` + fp64() + `","actor":"agent","phase":"build","engine":"","data":{"reason":"r"}}`,
		"fp missing on triaged": `{"ts":"2026-08-17T09:14:22Z","v":1,"event":"triaged","actor":"agent","phase":"build","engine":"x","data":{"reason":"r"}}`,
		"no data": `{"ts":"2026-08-17T09:14:22Z","v":1,"event":"deferred","fingerprint":"` + fp64() + `","actor":"agent","phase":"build","engine":"x"}`,
	}
	for name, line := range cases {
		if _, err := Decode([]byte(line)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDecodePreservesUnknownKind(t *testing.T) {
	line := `{"ts":"2026-08-17T09:14:22Z","v":1,"event":"frobnicated","actor":"agent","phase":"build","engine":"x","data":{"a":1}}`
	ev, err := Decode([]byte(line))
	if err != nil {
		t.Fatalf("unknown kinds must be preserved: %v", err)
	}
	if ev.Payload() != nil {
		t.Fatal("unknown kinds have no typed payload")
	}
	if !bytes.Contains(Canonical(ev), []byte(`"frobnicated"`)) {
		t.Fatal("unknown kind lost in canonical form")
	}
}
