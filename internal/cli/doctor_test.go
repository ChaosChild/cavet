package cli

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/store"
)

func TestDiffStateFindsLostVerdict(t *testing.T) {
	replay := &store.State{Findings: []*store.Finding{
		{Fingerprint: "aaaa1111", Status: "dismissed",
			Verdict: &store.Verdict{Verdict: "dismissed", Reason: "noise"}, InBaseline: true},
	}, Items: []store.Item{{ID: "it-abc123"}}}
	disk := &store.State{Findings: []*store.Finding{
		{Fingerprint: "aaaa1111", Status: "open", InBaseline: true},
	}, Items: []store.Item{}}

	d := diffState(disk, replay)
	if !d.found() || !d.safeToFix() {
		t.Fatal("log-derivable drift not detected as fixable")
	}
	out := d.String()
	for _, want := range []string{"aaaa1111", "verdict", "it-abc123"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestDiffStateDiskOnlyIsUnsafe(t *testing.T) {
	disk := &store.State{Findings: []*store.Finding{
		{Fingerprint: "bbbb2222", Status: "open"},
	}}
	d := diffState(disk, &store.State{})
	if !d.found() {
		t.Fatal("disk-only drift not detected")
	}
	if d.safeToFix() {
		t.Error("disk-only findings must refuse doctor fix")
	}
}

func TestDiffStateClean(t *testing.T) {
	replay := &store.State{Findings: []*store.Finding{
		{Fingerprint: "aaaa1111", Status: "open", InBaseline: true},
	}}
	d := diffState(replay, replay)
	if d.found() {
		t.Errorf("clean states reported as drift:\n%s", d.String())
	}
}

// --- fix-path integration (task brief step 6) ---

// fp64 pads a short id into a log-valid 64-hex fingerprint.
func fp64(seed string) string { return seed + strings.Repeat("0", 64-len(seed)) }

// snapshotState renders every file under .cavet/ as "path:size:sha256" lines,
// so a test can prove a code path wrote nothing anywhere in the artefact dir.
func snapshotState(t *testing.T, s *store.Store) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(s.Cavet, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.Cavet, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&b, "%s:%d:%x\n", filepath.ToSlash(rel), len(data), sum)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// newCliTestStore scaffolds a store in a fresh temp dir and points the command
// surface at it via cwd (repoRoot walks up from cwd; same pattern as
// TestRepoRootWalksUp in cli_test.go).
func newCliTestStore(t *testing.T) *store.Store {
	t.Helper()
	root := t.TempDir()
	s, err := store.Init(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	return s
}

func mustAppend(t *testing.T, s *store.Store, ev events.Event) {
	t.Helper()
	if err := s.Append(ev); err != nil {
		t.Fatal(err)
	}
}

func testDetected(fp string, at time.Time) events.Event {
	ev, err := events.NewDetected(at, events.ActorOperator, events.PhaseBuild,
		"cavet-engine:test", fp, events.DetectedData{
			Rule: "test.rule", Severity: events.SevHigh, Path: "main.go", Line: 1,
			Description: "test finding", Scanner: "trivy",
		})
	if err != nil {
		panic("testDetected: " + err.Error()) // static fixture, never varies
	}
	return ev
}

func testTriaged(fp, verdict string, at time.Time) events.Event {
	ev, err := events.NewTriaged(at, events.ActorOperator, events.PhaseBuild,
		"cavet-engine:test", fp, events.TriagedData{
			Verdict: events.Verdict(verdict), Confidence: events.ConfidenceHigh, Reason: "test verdict",
		})
	if err != nil {
		panic("testTriaged: " + err.Error()) // static fixture, never varies
	}
	return ev
}

// The 2026-09-07 incident shape: verdicts and statuses vanish from on-disk
// state while the log stays intact. doctorFixStore must restore them.
func TestDoctorFixRepairsLostVerdict(t *testing.T) {
	s := newCliTestStore(t)
	base := time.Now().UTC().Truncate(time.Second)
	mustAppend(t, s, testDetected(fp64("aaaa1111"), base))
	mustAppend(t, s, testTriaged(fp64("aaaa1111"), "dismissed", base.Add(time.Second)))
	if _, err := s.Rebuild(); err != nil {
		t.Fatal(err)
	}
	// corrupt: strip the verdict from the on-disk state, log stays intact
	disk, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	disk.Findings[0].Verdict = nil
	disk.Findings[0].Status = "open"
	if err := s.WriteState(disk); err != nil {
		t.Fatal(err)
	}
	if err := doctorFixStore(s); err != nil {
		t.Fatalf("fix on log-derivable drift must succeed: %v", err)
	}
	fixed, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed.Findings) != 1 {
		t.Fatalf("want 1 finding after fix, got %d", len(fixed.Findings))
	}
	f := fixed.Findings[0]
	if f.Verdict == nil || f.Verdict.Verdict != "dismissed" || f.Verdict.Reason != "test verdict" {
		t.Errorf("verdict not restored from log: %+v", f.Verdict)
	}
	if f.Status != "dismissed" {
		t.Errorf("status = %q, want dismissed (restored from the triaged event)", f.Status)
	}
}

// Disk-only rows are the data-loss shape: fix must refuse with the exit-1
// error and leave the on-disk state untouched.
func TestDoctorFixRefusesDiskOnly(t *testing.T) {
	s := newCliTestStore(t)
	base := time.Now().UTC().Truncate(time.Second)
	mustAppend(t, s, testDetected(fp64("aaaa1111"), base))
	if _, err := s.Rebuild(); err != nil {
		t.Fatal(err)
	}
	disk, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	disk.Findings = append(disk.Findings, &store.Finding{Fingerprint: fp64("bbbb2222"), Status: "open"})
	if err := s.WriteState(disk); err != nil {
		t.Fatal(err)
	}
	err = doctorFixStore(s)
	var ec *exitErr
	if !errors.As(err, &ec) || ec.code != 1 {
		t.Fatalf("disk-only drift must refuse with exitErr code 1, got %v", err)
	}
	after, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Findings) != 2 {
		t.Fatalf("refusal must leave disk state untouched, got %d findings", len(after.Findings))
	}
	if after.Findings[1].Fingerprint != fp64("bbbb2222") {
		t.Errorf("disk-only finding must survive the refusal: %+v", after.Findings[1])
	}
}

// The report path must never write into the real .cavet/: on a drifted store,
// every state file is byte-identical before and after the run.
func TestDoctorReportWritesNothing(t *testing.T) {
	s := newCliTestStore(t)
	base := time.Now().UTC().Truncate(time.Second)
	mustAppend(t, s, testDetected(fp64("aaaa1111"), base))
	mustAppend(t, s, testTriaged(fp64("aaaa1111"), "dismissed", base.Add(time.Second)))
	if _, err := s.Rebuild(); err != nil {
		t.Fatal(err)
	}
	disk, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	disk.Findings[0].Verdict = nil // drift the disk away from the log
	if err := s.WriteState(disk); err != nil {
		t.Fatal(err)
	}
	snap := snapshotState(t, s)
	if err := runDoctorReport(nil, nil); err == nil {
		t.Fatal("drifted store must exit 1 from the report path")
	}
	if got := snapshotState(t, s); got != snap {
		t.Errorf("report path wrote into the real .cavet/:\nbefore %s\nafter  %s", snap, got)
	}
}
