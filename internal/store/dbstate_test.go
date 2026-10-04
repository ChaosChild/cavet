package store

import (
	"testing"
	"time"
)

func TestDBStateRoundTrip(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.LoadDBState()
	if err != nil {
		t.Fatalf("missing state file must yield empty state: %v", err)
	}
	if len(st.Artifacts) != 0 {
		t.Fatalf("fresh state must be empty, got %v", st.Artifacts)
	}

	now := time.Now().UTC().Truncate(time.Second)
	st.Artifacts = map[string]DBArtifact{
		"vuln": {Digest: "sha256:aaa", UpdatedAt: now, SwappedAt: now, Source: "managed"},
		"java-db": {Digest: "sha256:bbb", UpdatedAt: now, SwappedAt: now,
			Source: "managed"},
	}
	if err := s.WriteDBState(st); err != nil {
		t.Fatal(err)
	}
	back, err := s.LoadDBState()
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Artifacts) != 2 || back.Artifacts["vuln"].Digest != "sha256:aaa" ||
		back.Artifacts["vuln"].Source != "managed" ||
		!back.Artifacts["vuln"].UpdatedAt.Equal(now) {
		t.Fatalf("round trip mismatch: %+v", back.Artifacts)
	}
	if back.Artifacts["java-db"].Digest != "sha256:bbb" {
		t.Fatalf("java-db entry lost: %+v", back.Artifacts)
	}
}
