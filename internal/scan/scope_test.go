package scan

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChaosChild/cavet/internal/engineclient"
)

// fakeRunner records commands and serves canned outputs; the one producer of
// the Runner seam (plan Task 14).
type fakeRunner struct {
	cmds    []string
	stdout  map[string]string // command substring → stdout
	stderr  map[string]string // command substring → stderr on its non-zero exit
	exit    map[string]int    // command substring → non-zero exit code
	reports map[string][]byte
	scans   int
}

func (f *fakeRunner) Exec(_ context.Context, cmd []string) (engineclient.ExecResult, error) {
	joined := strings.Join(cmd, " ")
	f.cmds = append(f.cmds, joined)
	for sub, code := range f.exit {
		if strings.Contains(joined, sub) {
			return engineclient.ExecResult{Code: code, Stderr: []byte(f.stderr[sub])}, nil
		}
	}
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

// The image-phase seam: record the call, and make SaveImage real enough that
// tar cleanup in .cavet/tmp is observable.
func (f *fakeRunner) BuildImage(_ context.Context, dockerfilePath, contextDir, tag, target string, _ io.Writer) error {
	cmd := "build " + dockerfilePath + " ctx " + contextDir + " tag " + tag
	if target != "" {
		cmd += " target " + target
	}
	f.cmds = append(f.cmds, cmd)
	return nil
}

func (f *fakeRunner) SaveImage(_ context.Context, ref, destPath string) error {
	f.cmds = append(f.cmds, "save "+ref+" "+destPath)
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(destPath, []byte("tar"), 0o644)
}

func (f *fakeRunner) CopyToContainer(_ context.Context, srcPath, dstPath string) error {
	f.cmds = append(f.cmds, "cp "+srcPath+" "+dstPath)
	return nil
}

func (f *fakeRunner) RemoveImage(_ context.Context, ref string) error {
	f.cmds = append(f.cmds, "rmi "+ref)
	return nil
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
		scope   Scope
		deep    bool
		checkov bool
		want    string
	}{
		{ScopeStaged, false, false, "gitleaks,trivy"},
		{ScopeDiff, false, false, "gitleaks,trivy"},
		{ScopeFull, false, false, "gitleaks,trivy,opengrep"},
		{ScopeStaged, true, false, "gitleaks,trivy,opengrep"},
		// The opt-in second IaC scanner joins every filesystem scope, fast
		// tier included: coverage must stay honest about what ran (spec §5.2).
		{ScopeStaged, false, true, "gitleaks,trivy,checkov"},
		{ScopeDiff, false, true, "gitleaks,trivy,checkov"},
		{ScopeFull, false, true, "gitleaks,trivy,checkov,opengrep"},
		{ScopeStaged, true, true, "gitleaks,trivy,checkov,opengrep"},
		// The image scope has no filesystem tier; the image phase is the scan.
		{ScopeImage, false, false, ""},
		{ScopeImage, true, true, ""},
	}
	for _, c := range cases {
		if got := strings.Join(TierScanners(c.scope, c.deep, c.checkov), ","); got != c.want {
			t.Errorf("TierScanners(%v, %v, %v) = %q, want %q", c.scope, c.deep, c.checkov, got, c.want)
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
			"/reports/trivy.json":     fixtureTrivyJSON("CVE-2024-1", "requirements.txt", 2),
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

// fixtureTrivyJSON builds a one-vulnerability trivy fs JSON document in the
// shape the pinned engine 0.74.0 emits (captured: .superpowers/sdd/spike/).
func fixtureTrivyJSON(ruleID, path string, line int) []byte {
	doc := fmt.Sprintf(`{"Results":[{"Target":%q,"Class":"lang-pkgs","Type":"npm",`+
		`"Packages":[{"ID":"pkg@1.0.0","Name":"pkg","Version":"1.0.0","Locations":[{"StartLine":%d}]}],`+
		`"Vulnerabilities":[{"VulnerabilityID":%q,"PkgID":"pkg@1.0.0","PkgName":"pkg",`+
		`"InstalledVersion":"1.0.0","Severity":"HIGH","Title":"pkg vuln"}]}]}`, path, line, ruleID)
	return []byte(doc)
}

// TestStageWorktreeCommand pins the diff staging pipeline: dash-safe (xargs
// consumes git's NUL list, no read loop), deletions excluded at the git
// level, scan dir created upfront so an empty diff still stages a valid empty
// target. The ref rides shQuote so odd refs compose into one shell word.
func TestStageWorktreeCommand(t *testing.T) {
	r := &fakeRunner{}
	if err := stageWorktree(context.Background(), r, "feature x", "/scan/1-1"); err != nil {
		t.Fatal(err)
	}
	want := "sh -c mkdir -p /scan/1-1 && cd /workspace && " +
		"git diff --name-only -z --diff-filter=ACMRT 'feature x' | " +
		"xargs -0 -r -I{} cp --parents -- {} /scan/1-1/"
	if len(r.cmds) != 1 || r.cmds[0] != want {
		t.Fatalf("stageWorktree command:\n got: %v\nwant: %q", r.cmds, want)
	}
}

// TestScopeCommandsAvoidDashBashisms is the static tripwire for the 0.2.x
// --diff outage: the engine's /bin/sh is dash, and a `read -d` consumer
// staged nothing while still exiting 0. String-pinned command tests cannot
// catch shell portability, so grep the command builders' own source,
// comments stripped (this file documents the bug in prose).
func TestScopeCommandsAvoidDashBashisms(t *testing.T) {
	b, err := os.ReadFile("scope.go")
	if err != nil {
		t.Skipf("scope.go not adjacent to test: %v", err)
	}
	var code []string
	for _, ln := range strings.Split(string(b), "\n") {
		if i := strings.Index(ln, "//"); i >= 0 {
			ln = ln[:i]
		}
		code = append(code, ln)
	}
	for _, bashism := range []string{"read -r -d", "read -d"} {
		if strings.Contains(strings.Join(code, "\n"), bashism) {
			t.Fatalf("scope.go contains %q outside comments: dash rejects it, staging would silently no-op", bashism)
		}
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
	case "checkov":
		// checkov strips the leading slash from scanned paths and always
		// carries a snippet (captured from engine checkov 3.3.16).
		doc = fmt.Sprintf(`{"runs":[{"tool":{"driver":{"name":"Checkov","rules":[{"id":%q,"defaultConfiguration":{"level":"error"}}]}},"results":[{"ruleId":%q,"ruleIndex":0,"level":"error","message":{"text":"policy"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q},"region":{"startLine":%d,"snippet":{"text":"resource"}}}}]}]}]}`, ruleID, ruleID, path, line)
	default:
		doc = fmt.Sprintf(`{"runs":[{"tool":{"driver":{"name":"Opengrep OSS","rules":[{"id":%q,"defaultConfiguration":{"level":"error"},"properties":{"tags":["CWE-89: x"]}}]}},"results":[{"ruleId":%q,"message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/workspace/%s"},"region":{"startLine":%d,"snippet":{"text":"code"}}}}]}]}]}`, ruleID, ruleID, path, line)
	}
	return []byte(doc)
}
