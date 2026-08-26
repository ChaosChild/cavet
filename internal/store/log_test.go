package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
)

const testEngine = "ghcr.io/x@sha256:a"

func seedEv(t *testing.T, s *Store) events.Event {
	t.Helper()
	ev, err := events.NewRaised(time.Now().UTC(), events.ActorOperator, events.PhaseDesign,
		testEngine, events.RaisedData{Kind: events.ItemDesign, Question: "q?"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

func globOne(t *testing.T, dir string) string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(m) != 1 {
		t.Fatalf("want exactly one log file, got %v (%v)", m, err)
	}
	return m[0]
}

func appendString(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func TestAppendRoundTrip(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	ev := seedEv(t, s)
	got, err := s.ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != events.Raised {
		t.Fatalf("got %+v", got)
	}
	if !bytes.Equal(events.Canonical(got[0].Event), events.Canonical(ev)) {
		t.Error("roundtrip changed canonical form")
	}
	if want := "events-" + time.Now().UTC().Format("2006-01") + ".jsonl"; got[0].File != want {
		t.Errorf("wrong rotation file %s want %s", got[0].File, want)
	}
}

func TestCorruptLineIsHardError(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	seedEv(t, s)
	appendString(t, globOne(t, filepath.Join(root, ".cavet", "log")), "{not json}\n")
	_, err = s.ReadLog()
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Line != 2 {
		t.Fatalf("want ParseError line 2, got %v", err)
	}
}

func TestPartialTailWarnsIgnored(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	seedEv(t, s)
	appendString(t, globOne(t, filepath.Join(root, ".cavet", "log")), `{"ts":"2026`) // no newline
	got, err := s.ReadLog()
	if err != nil {
		t.Fatalf("partial tail must not fail: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
}

func TestPartialLineMidFileIsHardError(t *testing.T) {
	root := t.TempDir()
	s, err := Init(root)
	if err != nil {
		t.Fatal(err)
	}
	seedEv(t, s)
	logFile := globOne(t, filepath.Join(root, ".cavet", "log"))
	appendString(t, logFile, `{"ts":"2026`+"\n") // truncated, but more follows
	ev, err := events.NewRaised(time.Now().UTC(), events.ActorOperator, events.PhaseDesign,
		testEngine, events.RaisedData{Kind: events.ItemDesign, Question: "after"})
	if err != nil {
		t.Fatal(err)
	}
	appendString(t, logFile, string(events.Canonical(ev))+"\n")
	_, err = s.ReadLog()
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("mid-file partial line must be a hard error, got %v", err)
	}
}
