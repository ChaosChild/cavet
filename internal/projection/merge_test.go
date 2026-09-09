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

// The dogfooding pair: gitleaks generic-api-key + opengrep's
// generic.secrets rule fire on the same span/path and must collapse to one
// finding (opt.opengrep-rules.generic.secrets.* is secret-category).
func TestSecretCollapseOpengrep(t *testing.T) {
	var all []Finding
	all = append(all, parseFixture(t, "testdata/secrets/a.sarif", "gitleaks", "")...)
	all = append(all, parseFixture(t, "testdata/secrets/c.sarif", "opengrep", "")...)
	if len(all) != 2 {
		t.Fatalf("want 2 raw findings, got %d", len(all))
	}

	merged := Merge(all)
	if len(merged) != 1 {
		t.Fatalf("opengrep secret must collapse with gitleaks, got %d findings", len(merged))
	}
	m := merged[0]
	if m.Scanner != "gitleaks" {
		t.Fatalf("originating scanner must be gitleaks, got %q", m.Scanner)
	}
	ogRule := "opt.opengrep-rules.generic.secrets.security.detected-generic-api-key"
	if len(m.AlsoDetectedBy) != 1 || m.AlsoDetectedBy[0] != ogRule {
		t.Fatalf("want the opengrep rule in also_detected_by, got %+v", m.AlsoDetectedBy)
	}
	if len(m.CollapsedWith) != 1 || m.CollapsedWith[0] != ogRule {
		t.Fatalf("want the opengrep rule in collapsed_with, got %+v", m.CollapsedWith)
	}
	if !m.Secret || m.RuleID != "generic-api-key" {
		t.Fatalf("winner keeps gitleaks rule id and secret flag, got %q secret=%v", m.RuleID, m.Secret)
	}
}

// Non-secrets under opengrep's generic subtree (dockerfile, html-templates…)
// must NOT join the secret collapse.
func TestOpengrepNonSecretStaysOut(t *testing.T) {
	fs := []Finding{
		{Scanner: "gitleaks", RuleID: "generic-api-key", Severity: "high", Path: "Dockerfile", Line: 3, Snippet: "Xk9mP2vL5nQ8wR3jT6yB4cF7hG1sD0eA"},
		{Scanner: "opengrep", RuleID: "opt.opengrep-rules.generic.dockerfile.best-practice.multiple-cmd-instructions", Severity: "medium", Path: "Dockerfile", Line: 3, Snippet: "Xk9mP2vL5nQ8wR3jT6yB4cF7hG1sD0eA"},
	}
	if merged := Merge(fs); len(merged) != 2 {
		t.Fatalf("non-secret opengrep rules must not collapse, got %d", len(merged))
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

// Image findings fingerprint on package identity in the img: namespace, never
// on line context (spec §3.3); the secret pre-collapse never applies.
func TestImageFindingsFingerprintOnPackageIdentity(t *testing.T) {
	fs := parseFixture(t, "../finding/testdata/trivy-image.sarif", "trivy-image", "Dockerfile")
	fs[0].ImageName, fs[1].ImageName = "cavet-scan-0", "cavet-scan-0"
	merged := Merge(fs)
	if len(merged) != 2 {
		t.Fatalf("distinct packages stay distinct, got %d", len(merged))
	}
	for _, m := range merged {
		if m.Secret {
			t.Fatal("trivy-image findings never join the secret collapse")
		}
	}
	want := fingerprint.Image("cavet-scan-0", "CVE-2026-14456", "libcrypto3", "3.5.7-r0")
	if merged[0].Fingerprint != want {
		t.Fatalf("fingerprint must be the img: identity, got %s want %s", merged[0].Fingerprint, want)
	}
	if merged[0].Fingerprint == fingerprint.Of(fingerprint.RuleKey("", "CVE-2026-14456"), "") {
		t.Fatal("img: namespace must not collide with line-context fingerprints")
	}
	if len(merged[0].Locations) != 1 || merged[0].Locations[0].Path != "Dockerfile" {
		t.Fatalf("image findings locate at the Dockerfile, got %+v", merged[0].Locations)
	}
}

// The same package in two configured images (distinct build tags) is two
// findings: identity is bound to the tag the scan built the image under.
func TestImageIdentityBoundToBuildTag(t *testing.T) {
	fs := parseFixture(t, "../finding/testdata/trivy-image.sarif", "trivy-image", "Dockerfile")
	fs[0].ImageName, fs[1].ImageName = "cavet-scan-0", "cavet-scan-0"
	twin := fs[0]
	twin.ImageName = "cavet-scan-1" // second configured Dockerfile, same CVE+pkg

	merged := Merge([]Finding{fs[0], fs[1], twin})
	if len(merged) != 3 {
		t.Fatalf("want 3 findings (2 image namespaces, 1 twin), got %d", len(merged))
	}
	sawTwin := false
	for _, m := range merged {
		if m.Fingerprint == fingerprint.Image("cavet-scan-1", "CVE-2026-14456", "libcrypto3", "3.5.7-r0") {
			sawTwin = true
		}
	}
	if !sawTwin {
		t.Fatalf("the second image's finding must keep its own identity, got %+v", merged)
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
