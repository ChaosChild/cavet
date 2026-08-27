package scan

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ChaosChild/cavet/internal/engineclient"
)

// fakeRunner records commands and serves canned outputs; the one producer of
// the Runner seam (plan Task 14).
type fakeRunner struct {
	cmds   []string
	stdout map[string]string // command substring → stdout
	reports map[string][]byte
	scans  int
}

func (f *fakeRunner) Exec(_ context.Context, cmd []string) (engineclient.ExecResult, error) {
	joined := strings.Join(cmd, " ")
	f.cmds = append(f.cmds, joined)
	for sub, out := range f.stdout {
		if strings.Contains(joined, sub) {
			return engineclient.ExecResult{Stdout: []byte(out)}, nil
		}
	}
	return engineclient.ExecResult{}, nil
}

func (f *fakeRunner) CopyOut(_ context.Context, path string) ([]byte, error) {
	b, ok := f.reports[path]
	if !ok {
		return nil, fmt.Errorf("no report at %s", path)
	}
	return b, nil
}

func (f *fakeRunner) NextScanDir() string {
	f.scans++
	return fmt.Sprintf("/scan/%d", f.scans)
}

func (f *fakeRunner) ran(sub string) bool {
	for _, c := range f.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestTierSelection(t *testing.T) {
	cases := []struct {
		scope Scope
		deep  bool
		want  string
	}{
		{ScopeStaged, false, "gitleaks,trivy"},
		{ScopeDiff, false, "gitleaks,trivy"},
		{ScopeFull, false, "gitleaks,trivy,opengrep"},
		{ScopeStaged, true, "gitleaks,trivy,opengrep"},
	}
	for _, c := range cases {
		if got := strings.Join(TierScanners(c.scope, c.deep), ","); got != c.want {
			t.Errorf("TierScanners(%v, %v) = %q, want %q", c.scope, c.deep, got, c.want)
		}
	}
}

func TestStagedEmptyIndexIsNothingStaged(t *testing.T) {
	r := &fakeRunner{stdout: map[string]string{"git diff --cached": ""}}
	res, err := Run(context.Background(), newTestStore(t), r, Options{Scope: ScopeStaged, Engine: "ghcr.io/x@sha256:t"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NothingStaged {
		t.Fatal("empty index must yield NothingStaged")
	}
	if r.ran("gitleaks") || r.ran("trivy") {
		t.Fatal("no scanner may run when nothing is staged")
	}
}

func TestStagedScanStagesIndexAndScansScanDir(t *testing.T) {
	r := &fakeRunner{
		stdout: map[string]string{"git diff --cached": "api/users.py\x00auth/tokens.py\x00"},
		reports: map[string][]byte{
			"/reports/gitleaks.sarif": fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":    fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
		},
	}
	res, err := Run(context.Background(), newTestStore(t), r, Options{Scope: ScopeStaged, Engine: "ghcr.io/x@sha256:t"})
	if err != nil {
		t.Fatal(err)
	}
	if res.NothingStaged {
		t.Fatal("staged content present; must scan")
	}
	if !r.ran("git checkout-index -z --prefix=/scan/") {
		t.Fatalf("staging must checkout-index into a scan dir, cmds: %v", r.cmds)
	}
	if !r.ran("gitleaks dir /scan/") || !r.ran("trivy fs") {
		t.Fatalf("scanners must target the scan dir, cmds: %v", r.cmds)
	}
	if r.ran("opengrep") {
		t.Fatal("staged fast tier must not run opengrep")
	}
	if len(res.Rows) != 2 {
		t.Fatalf("want 2 new findings, got %d", len(res.Rows))
	}
	if res.Counts.Confirmed != 2 || res.Counts.Baseline != 0 {
		t.Fatalf("counts wrong: %+v", res.Counts)
	}
	sawPaths := map[string]bool{}
	for _, row := range res.Rows {
		sawPaths[row.Path] = true
	}
	if !sawPaths["auth/tokens.py"] || !sawPaths["requirements.txt"] {
		t.Fatalf("staged scan paths must be repo-relative, rows: %+v", res.Rows)
	}
}

// fixtureSARIF builds a one-result document in each emitter's shape.
func fixtureSARIF(scanner, ruleID, path string, line int) []byte {
	var doc string
	switch scanner {
	case "gitleaks":
		doc = fmt.Sprintf(`{"runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":%q}]}},"results":[{"ruleId":%q,"message":{"text":"detected"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q},"region":{"startLine":%d,"snippet":{"text":"leaky"}}}}]}]}]}`, ruleID, ruleID, path, line)
	case "trivy":
		doc = fmt.Sprintf(`{"runs":[{"tool":{"driver":{"name":"Trivy","rules":[{"id":%q,"shortDescription":{"text":"pkg vuln"},"properties":{"tags":["vulnerability","security","HIGH"]}}]}},"results":[{"ruleId":%q,"ruleIndex":0,"level":"error","message":{"text":"P"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q},"region":{"startLine":%d}}}]}]}]}`, ruleID, ruleID, path, line)
	default:
		doc = fmt.Sprintf(`{"runs":[{"tool":{"driver":{"name":"Opengrep OSS","rules":[{"id":%q,"defaultConfiguration":{"level":"error"},"properties":{"tags":["CWE-89: x"]}}]}},"results":[{"ruleId":%q,"message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/workspace/%s"},"region":{"startLine":%d,"snippet":{"text":"code"}}}}]}]}]}`, ruleID, ruleID, path, line)
	}
	return []byte(doc)
}
