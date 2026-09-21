package projection

import (
	"encoding/json"
	"testing"
)

// Golden: the projected run is a pinned small document — one rule per unique
// RuleID, level from severity, dev property only on dev rows.
func TestTrivySARIFRunGolden(t *testing.T) {
	fs := []Finding{
		{Scanner: "trivy", RuleID: "CVE-2026-67213", Severity: "high", Path: "package-lock.json",
			Line: 6, Desc: "nanoid DoS", Dev: true},
		{Scanner: "trivy", RuleID: "CVE-2020-28500", Severity: "medium", Path: "package-lock.json",
			Line: 5, Desc: "lodash ReDoS"},
		{Scanner: "trivy", RuleID: "github-pat", Severity: "critical", Path: "creds.txt",
			Line: 3, Desc: "GitHub Personal Access Token"},
	}
	got, err := TrivySARIFRun(fs)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"Trivy","version":"0.74.0","rules":[{"id":"CVE-2026-67213","defaultConfiguration":{"level":"error"},"properties":{"tags":["security","HIGH"]}},{"id":"CVE-2020-28500","defaultConfiguration":{"level":"warning"},"properties":{"tags":["security","MEDIUM"]}},{"id":"github-pat","defaultConfiguration":{"level":"error"},"properties":{"tags":["security","CRITICAL"]}}]}},"results":[{"ruleId":"CVE-2026-67213","level":"error","message":{"text":"nanoid DoS"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"package-lock.json"},"region":{"startLine":6}}}],"properties":{"dev":true}},{"ruleId":"CVE-2020-28500","level":"warning","message":{"text":"lodash ReDoS"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"package-lock.json"},"region":{"startLine":5}}}]},{"ruleId":"github-pat","level":"error","message":{"text":"GitHub Personal Access Token"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"creds.txt"},"region":{"startLine":3}}}]}]}]}`
	if string(got) != want {
		t.Fatalf("projected run mismatch:\n got: %s\nwant: %s", got, want)
	}
}

// The projected run must survive a re-parse with a non-empty runs array and
// carry well-formed JSON (the merged report stitches it raw).
func TestTrivySARIFRunIsStitchable(t *testing.T) {
	got, err := TrivySARIFRun([]Finding{
		{Scanner: "trivy", RuleID: "DS-0026", Severity: "low", Path: "Dockerfile", Line: 1, Desc: "No HEALTHCHECK"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Properties struct {
					Dev bool `json:"dev"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("want one run, one result: %s", got)
	}
	if doc.Runs[0].Results[0].Properties.Dev {
		t.Error("prod row must not carry properties.dev")
	}
}
