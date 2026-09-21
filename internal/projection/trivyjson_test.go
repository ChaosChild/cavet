package projection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChaosChild/cavet/internal/fingerprint"
)

// The fixtures are trims of the Task-4 spike captures: trivy 0.74.0 fs, json
// and sarif produced by the identical scan command, differing only in --format
// (.superpowers/sdd/spike/report.md). They are the byte-level identity
// contract for the trivy JSON parse.
func trivyFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Table-driven parse of the captured fixture: one case per class, pinning the
// identity triple (RuleID, CWE, Snippet), location, severity and the Dev join.
func TestParseTrivyJSONFixture(t *testing.T) {
	fs, err := ParseTrivyJSON(trivyFixture(t, "trivy-fs.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 7 { // 4 vulns + 2 misconfigs + 1 secret in the trimmed capture
		t.Fatalf("want 7 findings, got %d: %+v", len(fs), fs)
	}
	byRule := map[string]Finding{}
	for _, f := range fs {
		byRule[f.RuleID] = f
	}
	cases := []struct {
		rule    string
		cwe     string // trivy 0.74 fs SARIF carries no CWE tags: JSON must not either
		sev     string
		path    string
		line    int
		dev     bool
		descHas string
	}{
		{"CVE-2021-23337", "", "high", "package-lock.json", 5, false, "command injection via template"},
		{"CVE-2020-28500", "", "medium", "package-lock.json", 5, false, "ReDoS"},
		{"CVE-2026-67213", "", "high", "package-lock.json", 6, true, "infinite loop"},
		{"CVE-2021-23566", "", "medium", "package-lock.json", 6, true, "Information disclosure"},
		{"DS-0002", "", "high", "Dockerfile", 5, false, "Image user should not be"},
		{"DS-0026", "", "low", "Dockerfile", 1, false, "No HEALTHCHECK defined"}, // no JSON StartLine: defaults to 1
		{"github-pat", "", "critical", "creds.txt", 3, false, "GitHub Personal Access Token"},
	}
	for _, c := range cases {
		f, ok := byRule[c.rule]
		if !ok {
			t.Errorf("rule %s missing from parse", c.rule)
			continue
		}
		if f.CWE != c.cwe {
			t.Errorf("%s: CWE = %q, want %q (JSON CweIDs must stay out of identity)", c.rule, f.CWE, c.cwe)
		}
		if f.Snippet != "" {
			t.Errorf("%s: Snippet = %q, want empty (SARIF path has none)", c.rule, f.Snippet)
		}
		if f.Severity != c.sev {
			t.Errorf("%s: severity = %q, want %q", c.rule, f.Severity, c.sev)
		}
		if f.Path != c.path || f.Line != c.line {
			t.Errorf("%s: location = %s:%d, want %s:%d", c.rule, f.Path, f.Line, c.path, c.line)
		}
		if f.Dev != c.dev {
			t.Errorf("%s: Dev = %v, want %v", c.rule, f.Dev, c.dev)
		}
		if !strings.Contains(f.Desc, c.descHas) {
			t.Errorf("%s: desc = %q, want it to contain %q", c.rule, f.Desc, c.descHas)
		}
		if f.Scanner != "trivy" {
			t.Errorf("%s: scanner = %q", c.rule, f.Scanner)
		}
	}
}

// Identity parity is the binding contract (spike GATE 3): the SAME scan parsed
// through the SARIF path and through ParseTrivyJSON must yield pairwise equal
// fingerprints, or the format switch re-rolls every trivy-fs baseline.
func TestTrivyJSONIdentityParityWithSARIF(t *testing.T) {
	jsonFs, err := ParseTrivyJSON(trivyFixture(t, "trivy-fs.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	sarifFs, warns, err := Parse("trivy", trivyFixture(t, "trivy-fs.sarif"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("SARIF parse warnings: %v", warns)
	}
	if len(jsonFs) != len(sarifFs) {
		t.Fatalf("row count diverged: json %d vs sarif %d", len(jsonFs), len(sarifFs))
	}
	byRule := map[string]Finding{}
	for _, f := range sarifFs {
		byRule[f.RuleID] = f
	}
	for _, jf := range jsonFs {
		sf, ok := byRule[jf.RuleID]
		if !ok {
			t.Errorf("rule %s has no SARIF twin", jf.RuleID)
			continue
		}
		jfp := fingerprint.Of(fingerprint.RuleKey(jf.CWE, jf.RuleID), normSpan(jf.Snippet))
		sfp := fingerprint.Of(fingerprint.RuleKey(sf.CWE, sf.RuleID), normSpan(sf.Snippet))
		if jfp != sfp {
			t.Errorf("%s: fingerprint diverged json %s vs sarif %s", jf.RuleID, jfp[:12], sfp[:12])
		}
		if jf.Path != sf.Path || jf.Line != sf.Line {
			t.Errorf("%s: location diverged json %s:%d vs sarif %s:%d",
				jf.RuleID, jf.Path, jf.Line, sf.Path, sf.Line)
		}
		if jf.Severity != sf.Severity {
			t.Errorf("%s: severity diverged json %s vs sarif %s", jf.RuleID, jf.Severity, sf.Severity)
		}
	}
}

// Dev labeling must come from the captured Packages[].Dev join (PkgID), not
// from any naming heuristic: nanoid rows dev, lodash rows not.
func TestParseTrivyJSONDevLabels(t *testing.T) {
	fs, err := ParseTrivyJSON(trivyFixture(t, "trivy-fs.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	dev, prod := 0, 0
	for _, f := range fs {
		switch {
		case f.RuleID == "CVE-2026-67213" || f.RuleID == "CVE-2021-23566":
			if !f.Dev {
				t.Errorf("%s must carry Dev (nanoid dev chain)", f.RuleID)
			}
			dev++
		case f.RuleID == "CVE-2021-23337" || f.RuleID == "CVE-2020-28500":
			if f.Dev {
				t.Errorf("%s must not carry Dev (lodash prod)", f.RuleID)
			}
			prod++
		}
	}
	if dev != 2 || prod != 2 {
		t.Fatalf("dev/prod counts = %d/%d, want 2/2", dev, prod)
	}
}
