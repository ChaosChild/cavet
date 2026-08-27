package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPipelineWritesEventsStateAndReport(t *testing.T) {
	s := newTestStore(t)
	r := &fakeRunner{
		stdout: map[string]string{"git diff --cached": "auth/tokens.py\x00"},
		reports: map[string][]byte{
			"/reports/gitleaks.sarif": fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":    fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
		},
	}
	res, err := Run(context.Background(), s, r, Options{Scope: ScopeStaged, Engine: "ghcr.io/x@sha256:t"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 {
		t.Fatalf("want 2 rows, got %+v", res.Rows)
	}
	if res.ScopeLabel != "staged" || strings.Join(res.Scanners, ",") != "gitleaks,trivy" {
		t.Fatalf("header data wrong: %+v", res)
	}

	// log carries detected (per location) + surfaced (per actionable finding)
	evs, err := s.ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	detected, surfaced := 0, 0
	for _, e := range evs {
		switch e.Kind {
		case events.Detected:
			detected++
		case events.Surfaced:
			surfaced++
		}
	}
	if detected != 2 || surfaced != 2 {
		t.Fatalf("want 2 detected + 2 surfaced events, got %d/%d", detected, surfaced)
	}

	// state written with display ids
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Findings) != 2 {
		t.Fatalf("findings.json must hold both findings, got %d", len(st.Findings))
	}
	for _, f := range st.Findings {
		if len(f.DisplayID) < 6 {
			t.Fatalf("display id not assigned: %+v", f)
		}
	}

	// merged report exists and carries both scanners' runs
	b, err := os.ReadFile(filepath.Join(s.Cavet, "reports", "latest.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 2 {
		t.Fatalf("merged SARIF must carry one run per scanner, got %d", len(doc.Runs))
	}
}

func TestFullScanTargetsWorkspace(t *testing.T) {
	s := newTestStore(t)
	r := &fakeRunner{
		reports: map[string][]byte{
			"/reports/gitleaks.sarif":  fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":    fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
			"/reports/opengrep.sarif": fixtureSARIF("opengrep", "py.sql", "api/users.py", 8),
		},
	}
	res, err := Run(context.Background(), s, r, Options{Scope: ScopeFull, Engine: "ghcr.io/x@sha256:t"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.ran("gitleaks detect --source /workspace") {
		t.Fatalf("full scans walk history, cmds: %v", r.cmds)
	}
	if !r.ran("trivy fs") || !r.ran("/workspace") || !r.ran("opengrep scan") {
		t.Fatalf("all three scanners must run against /workspace, cmds: %v", r.cmds)
	}
	if len(res.Rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(res.Rows))
	}
	// opengrep paths are /workspace-absolute in SARIF; rows must be repo-relative
	for _, row := range res.Rows {
		if strings.HasPrefix(row.Path, "/") {
			t.Fatalf("row paths must be repo-relative: %+v", res.Rows)
		}
	}
}
