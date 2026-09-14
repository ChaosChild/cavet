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

func TestParseTrivyImageFixture(t *testing.T) {
	// Captured from the engine's trivy (0.74.0) over a real image tar,
	// 2026-09-09. Two location shapes: the scan tar (OS packages) and in-image
	// file paths (language packages) – both meaningless repo-side, both must
	// yield the caller's Dockerfile path.
	fs, warns, err := Parse("trivy-image", fixture(t, "trivy-image.sarif"), "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	if len(fs) != 2 {
		t.Fatalf("fixture has 2 findings, got %d", len(fs))
	}
	for _, f := range fs {
		if f.Path != "Dockerfile" || f.Line != 1 {
			t.Fatalf("image findings locate at the Dockerfile, got %+v", f)
		}
		if f.PkgName == "" || f.PkgVersion == "" {
			t.Fatalf("package identity must parse from the message, got %+v", f)
		}
		if f.Snippet != "" {
			t.Fatalf("image findings carry no line context, got snippet %q", f.Snippet)
		}
	}
	os0 := fs[0]
	if os0.RuleID != "CVE-2026-14456" || os0.PkgName != "libcrypto3" || os0.PkgVersion != "3.5.7-r0" {
		t.Fatalf("OS package identity wrong: %+v", os0)
	}
	if os0.Severity != "high" {
		t.Fatalf("severity maps from rule tags, got %q", os0.Severity)
	}
	lang := fs[1]
	if lang.RuleID != "CVE-2025-8869" || lang.PkgName != "pip" || lang.PkgVersion != "25.0.1" {
		t.Fatalf("language package identity wrong: %+v", lang)
	}
	if lang.Severity != "medium" {
		t.Fatalf("severity maps from rule tags, got %q", lang.Severity)
	}
}

func TestParseTrivyImageDropsRowWithoutPackageIdentity(t *testing.T) {
	doc := []byte(`{"runs":[{"tool":{"driver":{"rules":[{"id":"CVE-1","properties":{"tags":["vulnerability","security","HIGH"]}}]}},"results":[
		{"ruleId":"CVE-1","ruleIndex":0,"message":{"text":"Package: openssl\nInstalled Version: 3.0.15-r1\nVulnerability CVE-1\nSeverity: HIGH"},
		 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"x.tar"},"region":{"startLine":1}}}]},
		{"ruleId":"CVE-2","ruleIndex":0,"message":{"text":"Package: openssl\nVulnerability CVE-2\nSeverity: HIGH"},
		 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"x.tar"},"region":{"startLine":1}}}]},
		{"ruleId":"CVE-3","ruleIndex":0,"message":{"text":"not a vulnerability result"},
		 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"x.tar"},"region":{"startLine":1}}}]}
	]}]}`)
	fs, warns, err := Parse("trivy-image", doc, "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].PkgName != "openssl" || fs[0].PkgVersion != "3.0.15-r1" {
		t.Fatalf("incomplete package identity must drop the row, got %+v", fs)
	}
	if len(warns) != 2 {
		t.Fatalf("both incomplete rows drop with warnings, got %v", warns)
	}
	for _, w := range warns {
		if !strings.Contains(w, "trivy-image") {
			t.Fatalf("warnings must name the scanner: %v", warns)
		}
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
