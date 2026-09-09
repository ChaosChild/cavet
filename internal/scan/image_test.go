package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/fingerprint"
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
			"/reports/trivy-image-0.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
			"/reports/trivy-image-1.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
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
	if strings.Count(strings.Join(r.cmds, "\n"), "rmi cavet-scan-") != 2 {
		t.Fatalf("each built image must be removed under its own tag, cmds: %v", r.cmds)
	}
	// The same CVE+package in both images stays two findings: identity is
	// bound to the configured Dockerfile path each image came from (img:
	// namespace), not the transient build tag.
	if len(res.Rows) != 2 || res.Rows[0].Rule != "CVE-2024-9" {
		t.Fatalf("want one row per image, got %+v", res.Rows)
	}
	for _, row := range res.Rows {
		if row.Sev != "high" {
			t.Fatalf("trivy-image severities must map like trivy, got %q", row.Sev)
		}
		if row.Path != "Dockerfile" && row.Path != "engine/Dockerfile" {
			t.Fatalf("image rows locate at the Dockerfile, got %q", row.Path)
		}
	}
	fps := map[string]bool{res.Rows[0].FP: true, res.Rows[1].FP: true}
	if !fps[fingerprint.Image("Dockerfile", "CVE-2024-9", "openssl", "3.0.15-r1")] ||
		!fps[fingerprint.Image("engine/Dockerfile", "CVE-2024-9", "openssl", "3.0.15-r1")] {
		t.Fatalf("fingerprints must be per-image img: identities, got %v", fps)
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
		t.Fatalf("merged report must carry one run per image, got %d", doc.Runs)
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

// A failed trivy-image exec on the second image must fail the scan even
// though both per-image reports are present: /reports persists in the
// container, and without the per-image name plus exit-code gate CopyOut
// would hand back a stale report, re-attributing the wrong image's findings
// or masking the failure as a clean scan.
func TestImageScanFailedExecCannotReuseStaleReport(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	seedDockerfile(t, filepath.Join(s.Root, "engine", "Dockerfile"))
	r := &fakeRunner{
		exit: map[string]int{"--input /scan/image-1.tar": 1},
		reports: map[string][]byte{
			"/reports/trivy-image-0.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
			"/reports/trivy-image-1.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
		},
	}
	_, err := Run(context.Background(), s, r, Options{
		Scope: ScopeImage, Images: []string{"Dockerfile", "engine/Dockerfile"},
		Engine: "ghcr.io/x@sha256:t",
	})
	if err == nil || !strings.Contains(err.Error(), "trivy-image scan failed (exit 1)") {
		t.Fatalf("a failed trivy-image exec must fail the scan despite CopyOut succeeding, got %v", err)
	}
}

func TestFullScanIncludesImagePhase(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	r := &fakeRunner{
		reports: map[string][]byte{
			"/reports/gitleaks.sarif":      fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":         fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
			"/reports/opengrep.sarif":      fixtureSARIF("opengrep", "py.sql", "api/users.py", 8),
			"/reports/trivy-image-0.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
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
			"/reports/gitleaks.sarif":      fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":         fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
			"/reports/opengrep.sarif":      fixtureSARIF("opengrep", "py.sql", "api/users.py", 8),
			"/reports/trivy-image-0.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
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
		"/reports/gitleaks.sarif":      fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
		"/reports/trivy.sarif":         fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
		"/reports/trivy-image-0.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
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

// The coverage pair at the heart of the img: namespace (spec §3.1): a
// trivy-image finding is remediated only by an image scan covering its
// Dockerfile. A plain fs scan covering the same Dockerfile path – even a
// --full scan – did not run the originating scanner, so it proves nothing
// (scannerRan gate, delta.go).
func TestImageFindingDeltaCoverage(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	imageReport := fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH")
	cleanImageReport := []byte(`{"runs":[{"tool":{"driver":{"name":"Trivy","rules":[]}},"results":[]}]}`)
	fsReports := func() map[string][]byte {
		return map[string][]byte{
			"/reports/gitleaks.sarif":      fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":         fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
			"/reports/trivy-image-0.sarif": imageReport,
		}
	}
	wantFP := fingerprint.Image("Dockerfile", "CVE-2024-9", "openssl", "3.0.15-r1")

	// 1. First image scan: one image finding enters state with its img:
	// identity, Dockerfile location, and trivy-image as originating scanner.
	if _, err := Run(context.Background(), s, &fakeRunner{reports: fsReports()}, Options{
		Scope: ScopeImage, Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Findings) != 1 {
		t.Fatalf("one image finding expected, got %+v", st.Findings)
	}
	f := st.Findings[0]
	if f.Fingerprint != wantFP || f.OriginatingScanner != "trivy-image" {
		t.Fatalf("identity/scanner wrong: %s %s", f.Fingerprint, f.OriginatingScanner)
	}
	if len(f.Locations) != 1 || f.Locations[0].Path != "Dockerfile" {
		t.Fatalf("image finding must locate at the Dockerfile, got %+v", f.Locations)
	}

	// 2. Repeat image scan: same identity, same location – no duplicate
	// detected events, only surfaced.
	if _, err := Run(context.Background(), s, &fakeRunner{reports: fsReports()}, Options{
		Scope: ScopeImage, Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}

	// 3. Plain fs scans covering the Dockerfile path must NOT remediate it.
	// The scannerRan gate: gitleaks+trivy ran, trivy-image did not.
	if _, err := Run(context.Background(), s, &fakeRunner{
		stdout: map[string]string{"git diff --name-only": "Dockerfile\x00"},
		reports: map[string][]byte{
			"/reports/gitleaks.sarif": fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":    fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
		},
	}, Options{
		Scope: ScopeDiff, DiffRef: "HEAD~1", Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}
	// A --full fs scan (coverage AllPaths, still no trivy-image) is the
	// stronger case: every path covered, scanner still absent.
	if _, err := Run(context.Background(), s, &fakeRunner{
		reports: map[string][]byte{
			"/reports/gitleaks.sarif": fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":    fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
			"/reports/opengrep.sarif": fixtureSARIF("opengrep", "py.sql", "api/users.py", 8),
		},
	}, Options{Scope: ScopeFull, Engine: "ghcr.io/x@sha256:t"}); err != nil {
		t.Fatal(err)
	}
	evs, err := s.ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	detected, remediated := 0, 0
	for _, e := range evs {
		switch e.Kind {
		case events.Detected:
			if e.Fingerprint == wantFP {
				detected++
			}
		case events.Remediated:
			remediated++
		}
	}
	if detected != 1 || remediated != 0 {
		t.Fatalf("fs coverage must not remediate an image finding, and repeats must not re-detect: %d detected, %d remediated", detected, remediated)
	}
	st, err = s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	survived := false
	for _, f := range st.Findings {
		if f.Fingerprint == wantFP {
			survived = true
		}
	}
	if !survived {
		t.Fatalf("image finding must survive fs scans, got %+v", st.Findings)
	}

	// 4. The image scan that covers its Dockerfile remediates it.
	if _, err := Run(context.Background(), s, &fakeRunner{
		reports: map[string][]byte{"/reports/trivy-image-0.sarif": cleanImageReport},
	}, Options{
		Scope: ScopeImage, Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}
	evs, err = s.ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	var remediatedFP string
	for _, e := range evs {
		if e.Kind == events.Remediated {
			remediatedFP = e.Fingerprint
		}
	}
	if remediatedFP != wantFP {
		t.Fatalf("covering image scan must emit the remediation, last remediated fp %q", remediatedFP)
	}
	st, err = s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range st.Findings {
		if f.Fingerprint == wantFP {
			t.Fatalf("remediated image finding must leave state, got %+v", st.Findings)
		}
	}
}

// Reordering container_images changes the transient build tags (the salted
// tags swap ordinals) but must not re-identify image findings: identity
// derives from the Dockerfile path, so the reorder scan emits neither fresh
// detected nor false remediated events (design D3).
func TestImageIdentitySurvivesListReordering(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	seedDockerfile(t, filepath.Join(s.Root, "engine", "Dockerfile"))
	reports := func() map[string][]byte {
		return map[string][]byte{
			"/reports/trivy-image-0.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
			"/reports/trivy-image-1.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
		}
	}
	run := func(images []string) {
		t.Helper()
		if _, err := Run(context.Background(), s, &fakeRunner{reports: reports()}, Options{
			Scope: ScopeImage, Images: images, Engine: "ghcr.io/x@sha256:t",
		}); err != nil {
			t.Fatal(err)
		}
	}
	run([]string{"Dockerfile", "engine/Dockerfile"})
	run([]string{"engine/Dockerfile", "Dockerfile"}) // reordered

	evs, err := s.ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	detected, remediated := 0, 0
	for _, e := range evs {
		switch e.Kind {
		case events.Detected:
			detected++
		case events.Remediated:
			remediated++
		}
	}
	if detected != 2 || remediated != 0 {
		t.Fatalf("reordering must keep identities: got %d detected, %d remediated", detected, remediated)
	}
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Findings) != 2 {
		t.Fatalf("one finding per configured image expected, got %+v", st.Findings)
	}
}

// The transient tag must be unique per repository root AND per scan: two
// cavet processes in different repositories share one daemon, and two
// overlapping scans in the SAME repository (a long scan plus a pre-commit
// hook) share the root salt, so colliding tags would let one overwrite the
// other's image between build and save.
func TestImageTagSaltedByRepoRoot(t *testing.T) {
	buildTag := func(s *store.Store) string {
		seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
		r := &fakeRunner{reports: map[string][]byte{
			"/reports/trivy-image-0.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
		}}
		if _, err := Run(context.Background(), s, r, Options{
			Scope: ScopeImage, Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
		}); err != nil {
			t.Fatal(err)
		}
		for _, c := range r.cmds {
			if strings.HasPrefix(c, "build ") {
				return c[strings.LastIndex(c, " ")+1:]
			}
		}
		t.Fatal("no build command recorded")
		return ""
	}
	// Fresh repository root per call: the tags must differ per root.
	a, b := buildTag(newTestStore(t)), buildTag(newTestStore(t))
	if a == b || !strings.HasPrefix(a, "cavet-scan-") || !strings.Contains(a, "-0-") {
		t.Fatalf("tags must follow cavet-scan-<hash>-<n>-<rand> and differ per repository root: %q vs %q", a, b)
	}
	// One repository scanned twice: the root salt matches, the per-scan
	// randomness must still keep the tags apart.
	s := newTestStore(t)
	first, second := buildTag(s), buildTag(s)
	if first == second {
		t.Fatal("two scans of one repository must not collide on the transient tag")
	}
}

// stagedDiverges pins the index-vs-worktree comparison the staged image
// phase warns on: git diff-files --quiet, exit 0 is not divergence, exit 1
// is (git's filter-aware comparison, so a CRLF-smudged worktree matches its
// LF index blob).
func TestStagedDiverges(t *testing.T) {
	s := newTestStore(t)
	host := filepath.Join(s.Root, "Dockerfile")
	seedDockerfile(t, host) // writes "FROM scratch\n"
	r := &fakeRunner{exit: map[string]int{"git diff-files --quiet -- Dockerfile": 0}}
	if div, err := stagedDiverges(context.Background(), r, "Dockerfile"); err != nil || div {
		t.Fatalf("identical index and worktree must not diverge: %v %v", div, err)
	}
	if !r.ran("git diff-files --quiet -- Dockerfile") {
		t.Fatalf("comparison must use filter-aware git diff-files, cmds: %v", r.cmds)
	}
	r = &fakeRunner{exit: map[string]int{"git diff-files --quiet": 1}}
	if div, err := stagedDiverges(context.Background(), r, "Dockerfile"); err != nil || !div {
		t.Fatalf("differing index and worktree must diverge: %v %v", div, err)
	}
}

// A staged Dockerfile whose working-tree copy diverges from the index warns
// and still scans: partial staging must not silently skip the image phase.
func TestStagedImageScanProceedsOnDivergence(t *testing.T) {
	s := newTestStore(t)
	seedDockerfile(t, filepath.Join(s.Root, "Dockerfile"))
	r := &fakeRunner{
		stdout: map[string]string{
			"git diff --cached": "Dockerfile\x00",
		},
		exit: map[string]int{
			// git diff-files --quiet exit 1: the index holds the CVE, the
			// working tree holds the fix.
			"git diff-files --quiet": 1,
		},
		reports: map[string][]byte{
			"/reports/gitleaks.sarif":      fixtureSARIF("gitleaks", "generic-api-key", "auth/tokens.py", 4),
			"/reports/trivy.sarif":         fixtureSARIF("trivy", "CVE-2024-1", "requirements.txt", 2),
			"/reports/trivy-image-0.sarif": fixtureImageSARIF("CVE-2024-9", "openssl", "3.0.15-r1", "HIGH"),
		},
	}
	if _, err := Run(context.Background(), s, r, Options{
		Scope: ScopeStaged, Images: []string{"Dockerfile"}, Engine: "ghcr.io/x@sha256:t",
	}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("trivy image --input /scan/image-0.tar") {
		t.Fatalf("divergent staged Dockerfile must still build and scan, cmds: %v", r.cmds)
	}
}

// fixtureImageSARIF builds a one-result trivy-image document in the real shape
// captured from engine trivy 0.74.0 (2026-09-09): package identity rides the
// result message lines, the SARIF uri is the scan tar, rules carry the
// severity tag.
func fixtureImageSARIF(vulnID, pkg, version, severity string) []byte {
	doc := fmt.Sprintf(`{"runs":[{"tool":{"driver":{"name":"Trivy","rules":[{"id":%q,"shortDescription":{"text":"pkg vuln"},"properties":{"tags":["vulnerability","security",%q]}}]}},"results":[{"ruleId":%q,"ruleIndex":0,"level":"error","message":{"text":"Package: %s\nInstalled Version: %s\nVulnerability %s\nSeverity: %s\nFixed Version: 9.9\nLink: [%s](https://avd.aquasec.com/nvd/%s)"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/scan/image-0.tar","uriBaseId":"ROOTPATH"},"region":{"startLine":1,"startColumn":1,"endLine":1,"endColumn":1}}}]}]}]}`,
		vulnID, severity, vulnID, pkg, version, vulnID, severity, vulnID, vulnID)
	return []byte(doc)
}
