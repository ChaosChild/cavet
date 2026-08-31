package output

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "regenerate golden files")

func assertGolden(t *testing.T, got, name string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("golden %s: %v (run with -update)", name, err)
	}
	if got != string(want) {
		t.Errorf("golden %s mismatch:\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}

// TestGoldenReference pins instance zero: spec §4.1's reference block
// (cli-spec §9).
func TestGoldenReference(t *testing.T) {
	view := ScanView{
		Scope: "staged", Scanners: []string{"gitleaks", "trivy"}, Phase: "build",
		EngineShort: "cavet-engine@sha256:4f2a…",
		Counts: Counts{
			Confirmed: 2, ConfirmedHigh: 1, ConfirmedLow: 1, High: 1, Medium: 1,
			Dismissed: 14, Suppressed: 0, Baseline: 347,
		},
		Findings: []FindingView{
			{ID: "a3f9c2", Sev: "high", Rule: "py.sql-injection", Path: "api/users.py", Line: 88, Desc: "user input concatenated into query", Conf: "high"},
			{ID: "7b1e04", Sev: "medium", Rule: "generic.weak-hash", Path: "auth/tokens.py", Line: 23, Desc: "MD5 used for token derivation", Conf: "low"},
		},
		Hints: []string{"cavet finding a3f9c2 --full", "cavet log --fingerprint 7b1e04"},
	}
	assertGolden(t, RenderResult(view), "golden/reference.md")
}

// Confidence is visible per row and in the aggregate (cli-spec §16.22).
func TestConfidenceMarkers(t *testing.T) {
	got := RenderResult(ScanView{
		Scope: "staged", Scanners: []string{"gitleaks"}, Phase: "build",
		Counts: Counts{Confirmed: 2, ConfirmedHigh: 1, ConfirmedLow: 1, High: 2},
		Findings: []FindingView{
			{ID: "a3f9c2", Sev: "high", Rule: "r", Path: "a.py", Line: 1, Conf: "high"},
			{ID: "7b1e04", Sev: "high", Rule: "r", Path: "b.py", Line: 2, Conf: "low"},
		},
	})
	for _, want := range []string{
		"2 confirmed (2 high): 1 high confidence, 1 low confidence",
		"| a3f9c2 | high* |",
		"| 7b1e04 | high^ |",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	// Untriaged rows keep the bare severity; zero-confirmed stays compact.
	bare := RenderResult(ScanView{
		Scope: "staged", Scanners: []string{"gitleaks"}, Phase: "build",
		Findings: []FindingView{{ID: "a3f9c2", Sev: "high", Rule: "r", Path: "a.py", Line: 1}},
	})
	if !strings.Contains(bare, "| a3f9c2 | high |") || strings.Contains(bare, "high confidence") {
		t.Fatalf("untriaged row must be bare and aggregate compact:\n%s", bare)
	}
}

func TestEmptyStates(t *testing.T) {
	got := RenderResult(ScanView{Scanners: []string{"gitleaks", "trivy"}})
	if !strings.Contains(got, "0 new findings") {
		t.Fatalf("empty state must be explicit: %q", got)
	}
	if strings.Contains(got, "baseline") {
		t.Fatalf("baseline must be hidden when none exists: %q", got)
	}
	if strings.Contains(got, "next:") {
		t.Fatalf("no hints, no next block: %q", got)
	}
}

func TestSortOrder(t *testing.T) {
	view := ScanView{
		Scope: "full", Scanners: []string{"opengrep"}, Phase: "build",
		Findings: []FindingView{
			{ID: "ffffff", Sev: "low", Rule: "r", Path: "a.py", Line: 1},
			{ID: "cccccc", Sev: "critical", Rule: "r", Path: "b.py", Line: 5},
			{ID: "dddddd", Sev: "high", Rule: "r", Path: "z.py", Line: 9},
			{ID: "eeeeee", Sev: "high", Rule: "r", Path: "a.py", Line: 10},
			{ID: "aaaaaa", Sev: "high", Rule: "r", Path: "a.py", Line: 2},
		},
	}
	got := RenderResult(view)
	order := []string{"cccccc", "aaaaaa", "eeeeee", "dddddd", "ffffff"}
	pos := 0
	for _, id := range order {
		i := strings.Index(got[pos:], id)
		if i < 0 {
			t.Fatalf("id %s missing or out of order in:\n%s", id, got)
		}
		pos += i + len(id)
	}
}

func TestDescriptionTruncatedAt60(t *testing.T) {
	long := strings.Repeat("x", 100)
	got := RenderResult(ScanView{
		Scope: "full", Scanners: []string{"opengrep"}, Phase: "build",
		Findings: []FindingView{{ID: "aaaaaa", Sev: "high", Rule: "r", Path: "a.py", Line: 1, Desc: long}},
	})
	if strings.Contains(got, long) {
		t.Fatal("description must be truncated")
	}
	if !strings.Contains(got, strings.Repeat("x", 59)+"…") {
		t.Fatalf("want 59 chars + ellipsis, got:\n%s", got)
	}
}
