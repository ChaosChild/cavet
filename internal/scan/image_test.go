package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/store"
)

func seedDockerfile(t *testing.T, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(s), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s, []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestImageScanBuildsAndScansConfiguredImages(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	seedDockerfile(t, filepath.Join(s.Root, "engine", "Dockerfile"))
	r := &fakeRunner{
		reports: map[string][]byte{
			"/reports/trivy-image.sarif": fixtureSARIF("trivy", "CVE-2024-9", "app/lib.py", 1),
		},
	}
	res, err := Run(context.Background(), s, r, Options{
		Scope: ScopeImage, Images: []string{"Dockerfile", "engine/Dockerfile"},
		Engine: "ghcr.io/x@sha256:t",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Scanners, ",") != "trivy-image" || res.ScopeLabel != "image" {
		t.Fatalf("image scan header wrong: %+v", res)
	}
	// Both images build and scan sequentially, per-image tars.
	if !r.ran("build "+filepath.Join(s.Root, "Dockerfile")+" ") || !r.ran("engine"+string(filepath.Separator)+"Dockerfile") {
		t.Fatalf("both Dockerfiles must build, cmds: %v", r.cmds)
	}
	if !r.ran("trivy image --input /scan/image-0.tar") || !r.ran("/scan/image-1.tar") {
		t.Fatalf("trivy must run per image tar, cmds: %v", r.cmds)
	}
	if !r.ran("rmi cavet-scan-0") || !r.ran("rmi cavet-scan-1") {
		t.Fatalf("built images must be removed, cmds: %v", r.cmds)
	}
	// Identical per-image findings merge into one run's rows.
	if len(res.Rows) != 1 || res.Rows[0].Rule != "CVE-2024-9" {
		t.Fatalf("want the merged trivy-image finding, got %+v", res.Rows)
	}
	if res.Rows[0].Sev != "high" {
		t.Fatalf("trivy-image severities must map like trivy, got %q", res.Rows[0].Sev)
	}
	// Tars are transient: tmp ends empty.
	entries, err := os.ReadDir(filepath.Join(s.Cavet, "tmp"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("image tars must be removed after the scan: %v %v", entries, err)
	}
	// The merged report carries one run per image.
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
		t.Fatalf("merged report must carry one run per image, got %d", len(doc.Runs))
	}
}

func TestImageScanWithoutConfigurationFails(t *testing.T) {
	s := newTestStore(t)
	_, err := Run(context.Background(), s, &fakeRunner{}, Options{Scope: ScopeImage, Engine: "ghcr.io/x@sha256:t"})
	if err == nil || !strings.Contains(err.Error(), "no container images configured") {
		t.Fatalf("--image with nothing configured must fail with guidance, got %v", err)
	}
}

func TestImageScanMissingDockerfileFails(t *testing.T) {
	s := newTestStore(t)
	_, err := Run(context.Background(), s, &fakeRunner{}, Options{
		Scope: ScopeImage, Images: []string{"gone/Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	})
	if err == nil || !strings.Contains(err.Error(), "gone/Dockerfile") {
		t.Fatalf("missing Dockerfile must fail naming it, got %v", err)
	}
}

func TestFullScanIncludesImagePhase(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	r := &fakeRunner{
		reports: map[string][]byte{
			"/reports/gitleaks.sarif":   fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":      fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
			"/reports/opengrep.sarif":   fixtureSARIF("opengrep", "py.sql", "api/users.py", 8),
			"/reports/trivy-image.sarif": fixtureSARIF("trivy", "CVE-2024-9", "app/lib.py", 1),
		},
	}
	res, err := Run(context.Background(), s, r, Options{
		Scope: ScopeFull, Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !r.ran("trivy image --input /scan/image-0.tar") {
		t.Fatalf("--full must run the image phase when configured, cmds: %v", r.cmds)
	}
	if strings.Join(res.Scanners, ",") != "gitleaks,trivy,opengrep,trivy-image" {
		t.Fatalf("scanners wrong: %v", res.Scanners)
	}
	if len(res.Rows) != 4 {
		t.Fatalf("want 3 fs findings + 1 image finding, got %d", len(res.Rows))
	}
}

// The init/rebaseline baseline flow: the full scan runs with Images from the
// config, then every state fingerprint, image findings included, lands in
// baseline.json so pre-existing image CVEs never arrive as detected events.
func TestBaselineWriteIncludesImageFindings(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	r := &fakeRunner{
		reports: map[string][]byte{
			"/reports/gitleaks.sarif":   fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":      fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
			"/reports/opengrep.sarif":   fixtureSARIF("opengrep", "py.sql", "api/users.py", 8),
			"/reports/trivy-image.sarif": fixtureSARIF("trivy", "CVE-2024-9", "app/lib.py", 1),
		},
	}
	if _, err := Run(context.Background(), s, r, Options{
		Scope: ScopeFull, Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	imageFP := ""
	var fps []string
	for _, f := range st.Findings {
		fps = append(fps, f.Fingerprint)
		f.InBaseline = true // the init/rebaseline baseline write (artefacts §6.3)
		if f.OriginatingScanner == "trivy-image" {
			imageFP = f.Fingerprint
		}
	}
	if imageFP == "" {
		t.Fatalf("the image finding must reach state, got %+v", st.Findings)
	}
	if err := s.WriteBaseline(store.Baseline{
		EngineDigest: "ghcr.io/x@sha256:t", CreatedAt: time.Now().UTC(), Fingerprints: fps,
	}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(s.Cavet, "state", "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bl store.Baseline
	if err := json.Unmarshal(b, &bl); err != nil {
		t.Fatal(err)
	}
	in := false
	for _, fp := range bl.Fingerprints {
		if fp == imageFP {
			in = true
		}
	}
	if !in {
		t.Fatalf("image finding must enter baseline.json, got %d fingerprints", len(bl.Fingerprints))
	}
}

func TestStagedScanImageTrigger(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	reports := map[string][]byte{
		"/reports/gitleaks.sarif":   fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
		"/reports/trivy.sarif":      fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
		"/reports/trivy-image.sarif": fixtureSARIF("trivy", "CVE-2024-9", "app/lib.py", 1),
	}
	// A configured Dockerfile among the staged paths pulls the image phase in.
	r := &fakeRunner{
		stdout:  map[string]string{"git diff --cached": "Dockerfile\x00auth/tokens.py\x00"},
		reports: reports,
	}
	if _, err := Run(context.Background(), s, r, Options{
		Scope: ScopeStaged, Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("trivy image --input /scan/image-0.tar") {
		t.Fatalf("staged Dockerfile must trigger the image phase, cmds: %v", r.cmds)
	}
	// Unstaged Dockerfiles do not.
	r2 := &fakeRunner{
		stdout:  map[string]string{"git diff --cached": "auth/tokens.py\x00"},
		reports: reports,
	}
	if _, err := Run(context.Background(), s, r2, Options{
		Scope: ScopeStaged, Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}
	if r2.ran("trivy image") {
		t.Fatalf("image phase must stay out without a staged Dockerfile, cmds: %v", r2.cmds)
	}
}

func TestDiffScanNeverRunsImagePhase(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	r := &fakeRunner{
		stdout: map[string]string{"git diff --name-only": "Dockerfile\x00"},
		reports: map[string][]byte{
			"/reports/gitleaks.sarif": fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":    fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
		},
	}
	if _, err := Run(context.Background(), s, r, Options{
		Scope: ScopeDiff, DiffRef: "HEAD~1", Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}
	if r.ran("trivy image") {
		t.Fatalf("diff scope must not run the image phase, cmds: %v", r.cmds)
	}
}
