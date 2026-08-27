package projection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "finding", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Spike-captured fixtures: real emitters, not synthetic JSON (cli-spec §15).

func TestParseOpengrepFixture(t *testing.T) {
	fs, warns, err := Parse("opengrep", fixture(t, "opengrep.sarif"), "/workspace")
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	if len(fs) != 7 {
		t.Fatalf("fixture has 7 planted findings, got %d", len(fs))
	}
	var sawCWE bool
	for _, f := range fs {
		if f.Severity == "" || f.Path == "" || f.RuleID == "" || f.Desc == "" {
			t.Fatalf("incomplete finding %+v", f)
		}
		if strings.HasPrefix(f.Path, "/") {
			t.Errorf("target prefix not stripped: %q", f.Path)
		}
		if strings.Contains(f.Desc, "\n") {
			t.Errorf("description must be one line: %q", f.Desc)
		}
		if f.CWE == "CWE-89" {
			sawCWE = true
		}
	}
	if !sawCWE {
		t.Error("expected a CWE-89 finding in the fixture")
	}
}

func TestParseGitleaksFixture(t *testing.T) {
	fs, warns, err := Parse("gitleaks", fixture(t, "gitleaks.sarif"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.RuleID != "generic-api-key" || f.Path != "config.py" || f.Line != 9 {
		t.Fatalf("wrong finding %+v", f)
	}
	if f.Severity != "high" {
		t.Fatalf("gitleaks findings are high until triaged, got %q", f.Severity)
	}
	if strings.TrimSpace(f.Snippet) == "" {
		t.Fatal("snippet must carry the matched span for secret collapse")
	}
}

func TestParseTrivyFixture(t *testing.T) {
	fs, warns, err := Parse("trivy", fixture(t, "trivy.sarif"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	if len(fs) != 38 {
		t.Fatalf("fixture has 38 findings, got %d", len(fs))
	}
	var critical bool
	for _, f := range fs {
		if f.RuleID == "CVE-2019-20477" && f.Severity == "critical" {
			critical = true
		}
		if strings.HasPrefix(f.Path, "/") {
			t.Errorf("trivy paths must be repo-relative, got %q", f.Path)
		}
	}
	if !critical {
		t.Error("CVE-2019-20477 must parse as critical (severity from rule tags)")
	}
}

func TestSeverityMaps(t *testing.T) {
	cases := []struct{ scanner, in, want string }{
		{"trivy", "CRITICAL", "critical"},
		{"trivy", "HIGH", "high"},
		{"trivy", "MEDIUM", "medium"},
		{"trivy", "LOW", "low"},
		{"trivy", "UNKNOWN", "info"},
		{"trivy", "", "info"},
		{"opengrep", "error", "high"},
		{"opengrep", "warning", "medium"},
		{"opengrep", "INFO", "info"},
		{"gitleaks", "", "high"},
	}
	for _, c := range cases {
		if got := NormalizeSeverity(c.scanner, c.in); got != c.want {
			t.Errorf("NormalizeSeverity(%q, %q) = %q, want %q", c.scanner, c.in, got, c.want)
		}
	}
}

func TestParseDropsMalformedResultWithWarning(t *testing.T) {
	// Valid SARIF envelope, one result without any location: the row drops with
	// a warning, never a parse failure (cli-spec §9).
	doc := []byte(`{"runs":[{"tool":{"driver":{"rules":[]}},"results":[
		{"ruleId":"r1","message":{"text":"no location"}},
		{"ruleId":"r2","message":{"text":"ok"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":2}}}]}
	]}]}`)
	fs, warns, err := Parse("opengrep", doc, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || len(warns) != 1 {
		t.Fatalf("want 1 finding + 1 warning, got %d findings, %d warnings", len(fs), len(warns))
	}
	if !strings.Contains(warns[0], "opengrep") || !strings.Contains(warns[0], "r1") {
		t.Fatalf("warning must name scanner and rule: %q", warns[0])
	}
}
