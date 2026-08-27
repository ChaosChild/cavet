package projection

import (
	"os"
	"testing"

	"github.com/ChaosChild/cavet/internal/fingerprint"
)

func parseFixture(t *testing.T, path, scanner, target string) []Finding {
	t.Helper()
	fs, warns, err := Parse(scanner, readLocal(t, path), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	return fs
}

// The hand-built pair reports one secret under two scanner rule ids (spike §7).
// Merge must collapse them into a single finding before fingerprinting.
func TestSecretCollapse(t *testing.T) {
	var all []Finding
	all = append(all, parseFixture(t, "testdata/secrets/a.sarif", "gitleaks", "")...)
	all = append(all, parseFixture(t, "testdata/secrets/b.sarif", "trivy", "")...)
	if len(all) != 2 {
		t.Fatalf("want 2 raw findings, got %d", len(all))
	}

	merged := Merge(all)
	if len(merged) != 1 {
		t.Fatalf("secret must collapse to one finding, got %d", len(merged))
	}
	m := merged[0]
	if m.Scanner != "gitleaks" {
		t.Fatalf("originating scanner must be gitleaks (first/dedicated secret scanner), got %q", m.Scanner)
	}
	if len(m.CollapsedWith) != 1 || m.CollapsedWith[0] != "stripe-secret-token" {
		t.Fatalf("want CollapsedWith [stripe-secret-token], got %+v", m.CollapsedWith)
	}
	if !m.Secret {
		t.Fatal("collapsed finding must be marked secret")
	}
	if m.RuleID != "generic-api-key" {
		t.Fatalf("winner keeps its rule id, got %q", m.RuleID)
	}
	if len(m.Locations) != 1 {
		t.Fatalf("same path+line must dedup to one location, got %+v", m.Locations)
	}
	wantFP := fingerprint.Of(fingerprint.RuleKey("", "generic-api-key"), normSpan(all[0].Snippet))
	if m.Fingerprint != wantFP {
		t.Fatalf("fingerprint must come from the winning secret, got %s want %s", m.Fingerprint, wantFP)
	}
}

// Non-secret findings with the same rule+context but different locations merge
// into one finding with multiple locations (spec §3.3).
func TestMultiLocationMerge(t *testing.T) {
	fs := []Finding{
		{Scanner: "opengrep", RuleID: "py.sql", CWE: "CWE-89", Severity: "high", Path: "a.py", Line: 1, Snippet: "q = build(x)"},
		{Scanner: "opengrep", RuleID: "py.sql", CWE: "CWE-89", Severity: "high", Path: "b.py", Line: 2, Snippet: "q = build(x)"},
		{Scanner: "opengrep", RuleID: "py.sql", CWE: "CWE-89", Severity: "high", Path: "a.py", Line: 1, Snippet: "q = build(x)"},
	}
	merged := Merge(fs)
	if len(merged) != 1 {
		t.Fatalf("same fingerprint must merge, got %d", len(merged))
	}
	if len(merged[0].Locations) != 2 {
		t.Fatalf("want 2 distinct locations, got %+v", merged[0].Locations)
	}
}

// Distinct contexts stay distinct findings.
func TestDistinctContextsStayDistinct(t *testing.T) {
	fs := []Finding{
		{Scanner: "opengrep", RuleID: "py.sql", CWE: "CWE-89", Severity: "high", Path: "a.py", Line: 1, Snippet: "q = build(x)"},
		{Scanner: "opengrep", RuleID: "py.sql", CWE: "CWE-89", Severity: "high", Path: "a.py", Line: 9, Snippet: "cursor.execute(raw)"},
	}
	merged := Merge(fs)
	if len(merged) != 2 {
		t.Fatalf("different contexts are different findings, got %d", len(merged))
	}
}

func readLocal(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
