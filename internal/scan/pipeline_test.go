package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
	"testing"

	"github.com/ChaosChild/cavet/internal/engineclient"
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
			"/reports/trivy.json":     fixtureTrivyJSON("CVE-2024-1", "requirements.txt", 2),
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
			"/reports/gitleaks.sarif": fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.json":     fixtureTrivyJSON("CVE-2024-1", "requirements.txt", 2),
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

// scanners.dev-deps drives the trivy invocation: --include-dev-deps present
// when on, absent when off, and dev findings keep their marker into the rows.
func TestTrivyDevDepsFlagAndRows(t *testing.T) {
	devJSON := []byte(`{"Results":[{"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm",` +
		`"Packages":[` +
		`{"ID":"lodash@4.17.20","Name":"lodash","Version":"4.17.20","Locations":[{"StartLine":5}]},` +
		`{"ID":"nanoid@3.1.20","Name":"nanoid","Version":"3.1.20","Dev":true,"Locations":[{"StartLine":6}]}],` +
		`"Vulnerabilities":[` +
		`{"VulnerabilityID":"CVE-2021-23337","PkgID":"lodash@4.17.20","PkgName":"lodash",` +
		`"InstalledVersion":"4.17.20","Severity":"HIGH","Title":"lodash cmd injection"},` +
		`{"VulnerabilityID":"CVE-2026-67213","PkgID":"nanoid@3.1.20","PkgName":"nanoid",` +
		`"InstalledVersion":"3.1.20","Severity":"HIGH","Title":"nanoid DoS"}]}]}`)
	mk := func() (*store.Store, *fakeRunner) {
		return newTestStore(t), &fakeRunner{
			stdout: map[string]string{"git diff --cached": "package-lock.json\x00"},
			reports: map[string][]byte{
				"/reports/gitleaks.sarif": fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
				"/reports/trivy.json":     devJSON,
			},
		}
	}

	s, r := mk()
	res, err := Run(context.Background(), s, r, Options{Scope: ScopeStaged, DevDeps: true, Engine: "ghcr.io/x@sha256:t"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.ran("--include-dev-deps") {
		t.Fatalf("dev-deps on must pass --include-dev-deps to trivy, cmds: %v", r.cmds)
	}
	// Pin the exact argument slice: --include-dev-deps must sit right after
	// "trivy fs"; inserting it between --scanners and its value would orphan
	// the scanner list.
	wantCmd := "trivy fs --include-dev-deps --scanners vuln,misconfig,secret" +
		" --skip-db-update --skip-check-update --offline-scan" +
		" --skip-dirs /workspace/.cavet" +
		" --format json --output /reports/trivy.json /scan/1"
	gotCmd := ""
	for _, c := range r.cmds {
		if strings.HasPrefix(c, "trivy fs") {
			gotCmd = c
			break
		}
	}
	if gotCmd != wantCmd {
		t.Fatalf("trivy invocation:\n got: %s\nwant: %s", gotCmd, wantCmd)
	}
	if !res.DevIncluded {
		t.Error("result must record DevIncluded")
	}
	var devRows int
	for _, row := range res.Rows {
		switch row.Rule {
		case "CVE-2026-67213":
			if !row.Dev {
				t.Error("nanoid row must carry Dev")
			}
			devRows++
		case "CVE-2021-23337":
			if row.Dev {
				t.Error("lodash row must not carry Dev")
			}
		}
	}
	if devRows != 1 {
		t.Fatalf("want 1 dev row, got %d", devRows)
	}
	if res.Counts.Dev != 1 {
		t.Errorf("Counts.Dev = %d, want 1", res.Counts.Dev)
	}
	// State carries the flag so replays reproduce it.
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range st.Findings {
		if f.RuleID == "CVE-2026-67213" && !f.Dev {
			t.Error("dev flag must reach state findings")
		}
	}

	// Knob off: no flag, no dev markers. Without --include-dev-deps trivy
	// never reports dev-only packages, so the prod-only document is the
	// realistic shape.
	prodJSON := []byte(`{"Results":[{"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm",` +
		`"Packages":[` +
		`{"ID":"lodash@4.17.20","Name":"lodash","Version":"4.17.20","Locations":[{"StartLine":5}]}],` +
		`"Vulnerabilities":[` +
		`{"VulnerabilityID":"CVE-2021-23337","PkgID":"lodash@4.17.20","PkgName":"lodash",` +
		`"InstalledVersion":"4.17.20","Severity":"HIGH","Title":"lodash cmd injection"}]}]}`)
	s2, r2 := newTestStore(t), &fakeRunner{
		stdout: map[string]string{"git diff --cached": "package-lock.json\x00"},
		reports: map[string][]byte{
			"/reports/gitleaks.sarif": fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.json":     prodJSON,
		},
	}
	res2, err := Run(context.Background(), s2, r2, Options{Scope: ScopeStaged, Engine: "ghcr.io/x@sha256:t"})
	if err != nil {
		t.Fatal(err)
	}
	if r2.ran("--include-dev-deps") {
		t.Fatalf("dev-deps off must not pass --include-dev-deps, cmds: %v", r2.cmds)
	}
	if res2.DevIncluded || res2.Counts.Dev != 0 {
		t.Errorf("DevIncluded/Counts.Dev = %v/%d, want false/0", res2.DevIncluded, res2.Counts.Dev)
	}
	for _, row := range res2.Rows {
		if row.Dev {
			t.Error("no row may carry Dev when the knob is off")
		}
	}
}

// The trivy budget (Options.Timeout) rides both trivy invocations, and the fs
// invocation additionally skips cavet's own state directory: scanning .cavet
// logs, state and old reports is pure waste, and the 2026-10-04 field-test
// timeout fired on a file inside it. The image command never carries the
// skip: it reads a tar, not the workspace.
func TestTrivyTimeoutAndCavetStateSkip(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	mk := func() *fakeRunner {
		return &fakeRunner{reports: map[string][]byte{
			"/reports/gitleaks.sarif":      fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.json":          fixtureTrivyJSON("CVE-2024-1", "requirements.txt", 2),
			"/reports/opengrep.sarif":      fixtureSARIF("opengrep", "py.sql", "api/users.py", 8),
			"/reports/trivy-image-0.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
		}}
	}

	r := mk()
	if _, err := Run(context.Background(), s, r, Options{
		Scope: ScopeFull, Images: imgs("Dockerfile"), Timeout: "90m",
		Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}
	var fsCmd, imgCmd string
	for _, c := range r.cmds {
		if strings.HasPrefix(c, "trivy fs") {
			fsCmd = c
		}
		if strings.HasPrefix(c, "trivy image") {
			imgCmd = c
		}
	}
	wantFS := "trivy fs --scanners vuln,misconfig,secret" +
		" --skip-db-update --skip-check-update --offline-scan" +
		" --skip-dirs /workspace/.cavet --timeout 90m" +
		" --format json --output /reports/trivy.json /workspace"
	if fsCmd != wantFS {
		t.Fatalf("trivy fs invocation:\n got: %s\nwant: %s", fsCmd, wantFS)
	}
	wantImg := "trivy image --input /scan/image-0.tar" +
		" --offline-scan --skip-db-update --skip-check-update --timeout 90m" +
		" --format sarif --output /reports/trivy-image-0.sarif"
	if imgCmd != wantImg {
		t.Fatalf("trivy image invocation:\n got: %s\nwant: %s", imgCmd, wantImg)
	}

	// No Timeout set: neither command carries --timeout (trivy's own built-in
	// default applies), while the fs skip stays.
	s2 := newTestStore(t)
	seedDockerfile(t, filepath.Join(s2.Root, "Dockerfile"))
	r2 := mk()
	if _, err := Run(context.Background(), s2, r2, Options{
		Scope: ScopeFull, Images: imgs("Dockerfile"), Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}
	if r2.ran("--timeout") {
		t.Fatalf("unset budget must not pass --timeout, cmds: %v", r2.cmds)
	}
	if !r2.ran("--skip-dirs /workspace/.cavet") {
		t.Fatalf("fs skip must hold without a budget, cmds: %v", r2.cmds)
	}
}

func TestCheckovOptsInPerRepository(t *testing.T) {
	mk := func() (*store.Store, *fakeRunner) {
		return newTestStore(t), &fakeRunner{
			stdout: map[string]string{"git diff --cached": "infra/main.tf\x00"},
			reports: map[string][]byte{
				"/reports/gitleaks.sarif":              fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
				"/reports/trivy.json":                  fixtureTrivyJSON("CVE-2024-1", "requirements.txt", 2),
				"/reports/checkov/results_sarif.sarif": fixtureSARIF("checkov", "CKV_AWS_20", "infra/main.tf", 1),
			},
		}
	}

	s, r := mk()
	res, err := Run(context.Background(), s, r, Options{Scope: ScopeStaged, Checkov: true, Engine: "ghcr.io/x@sha256:t"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.ran("checkov -d") {
		t.Fatalf("opted-in checkov must join the tier, cmds: %v", r.cmds)
	}
	if !r.ran("--skip-framework secrets sast") {
		t.Fatalf("checkov's secret framework must stay off, cmds: %v", r.cmds)
	}
	if !r.ran("--soft-fail") {
		t.Fatalf("checkov must run soft-fail so found issues never look like engine failures, cmds: %v", r.cmds)
	}
	if strings.Join(res.Scanners, ",") != "gitleaks,trivy,checkov" {
		t.Fatalf("header must name checkov: %+v", res)
	}
	if len(res.Rows) != 3 {
		t.Fatalf("want 3 rows, got %+v", res.Rows)
	}

	// Off by default: the same scan must not exec checkov anywhere.
	s2, r2 := mk()
	res2, err := Run(context.Background(), s2, r2, Options{Scope: ScopeStaged, Engine: "ghcr.io/x@sha256:t"})
	if err != nil {
		t.Fatal(err)
	}
	if r2.ran("checkov") {
		t.Fatalf("checkov must not run without the opt-in, cmds: %v", r2.cmds)
	}
	if strings.Join(res2.Scanners, ",") != "gitleaks,trivy" {
		t.Fatalf("header must stay default: %+v", res2)
	}
}

// PR B: the vuln DB identity read once before Run flows into last-scan.json
// and onto the trivy vuln findings' detected events; a failed/absent read
// keeps the old shapes byte-for-byte.
func TestLastScanAndEventsRecordVulnDB(t *testing.T) {
	trivyJSON := []byte(`{"Results":[{"Target":"requirements.txt","Class":"lang-pkgs",
		"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1","PkgName":"flask","InstalledVersion":"1.0","Severity":"HIGH","Title":"bad"}],
		"Misconfigurations":[{"ID":"AVD-DS-0002","Title":"root","Severity":"HIGH"}]}]}`)
	mk := func() (*store.Store, *fakeRunner) {
		return newTestStore(t), &fakeRunner{
			stdout: map[string]string{"git diff --cached": "requirements.txt\x00"},
			reports: map[string][]byte{
				"/reports/gitleaks.sarif": fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
				"/reports/trivy.json":     trivyJSON,
			},
		}
	}
	updated := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	s, r := mk()
	if _, err := Run(context.Background(), s, r, Options{Scope: ScopeStaged,
		Engine: "ghcr.io/x@sha256:t",
		VulnDB: engineclient.DBInfo{Digest: "sha256:db1", UpdatedAt: updated, Source: "managed"}}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(s.Cavet, "state", "last-scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ls LastScan
	if err := json.Unmarshal(b, &ls); err != nil {
		t.Fatal(err)
	}
	db, ok := ls.DB["vuln"]
	if !ok || db.Digest != "sha256:db1" || db.Source != "managed" || db.UpdatedAt != updated.UTC().Format(time.RFC3339) {
		t.Fatalf("last-scan db record wrong: %+v", ls.DB)
	}
	evs, err := s.ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	var seenVuln, seenOther bool
	for _, e := range evs {
		if e.Kind != events.Detected {
			continue
		}
		d := e.Payload().(events.DetectedData)
		switch d.Rule {
		case "CVE-2024-1":
			seenVuln = true
			if d.DB != "sha256:db1" {
				t.Fatalf("vuln event must carry the digest, got %q", d.DB)
			}
		case "AVD-DS-0002":
			seenOther = true
			if d.DB != "" {
				t.Fatalf("misconfig event must not carry a digest, got %q", d.DB)
			}
		}
	}
	if !seenVuln || !seenOther {
		t.Fatalf("expected both detected events, got vuln=%v other=%v", seenVuln, seenOther)
	}

	// No DB read: no db key in last-scan.json, no db field on any event.
	s2, r2 := mk()
	if _, err := Run(context.Background(), s2, r2, Options{Scope: ScopeStaged,
		Engine: "ghcr.io/x@sha256:t"}); err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(filepath.Join(s2.Cavet, "state", "last-scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b2), `"db"`) {
		t.Fatalf("old shape must survive without a DB read: %s", b2)
	}
}
