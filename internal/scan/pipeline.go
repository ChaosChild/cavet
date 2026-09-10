// Package scan orchestrates one scan: scope resolution and staging inside the
// engine container, scanner invocation contracts, SARIF projection, and the
// delta fold against state (cli-spec §§6–8). Scanner exec runs outside the
// artefact lock; only the fold+append+rewrite critical section holds it (§14).
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ChaosChild/cavet/internal/config"
	"github.com/ChaosChild/cavet/internal/engineclient"
	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/lookup"
	"github.com/ChaosChild/cavet/internal/projection"
	"github.com/ChaosChild/cavet/internal/store"
)

// Runner is the engine seam: engineclient.Client satisfies it; tests fake it.
// The image methods are the Task-1 host-side plumbing the image phase drives.
type Runner interface {
	Exec(ctx context.Context, cmd []string) (engineclient.ExecResult, error)
	CopyOut(ctx context.Context, containerPath string) ([]byte, error)
	NextScanDir() string
	BuildImage(ctx context.Context, dockerfilePath, contextDir, tag, target string) error
	SaveImage(ctx context.Context, ref, destPath string) error
	CopyToContainer(ctx context.Context, srcPath, dstPath string) error
	RemoveImage(ctx context.Context, ref string) error
}

type Options struct {
	Scope   Scope
	DiffRef string
	Images  []config.ImageEntry // configured Dockerfiles plus build targets (scan.container_images)
	Deep    bool
	Actor   events.Actor
	Phase   events.Phase
	Context events.SurfaceContext
	Engine  string // engine ref recorded on every event (artefacts §2.1)
}

// Row is one confirmed-or-open finding for the result table. Confidence is
// the verdict confidence (high|low) when triaged; Secret drives state-derived
// next hints.
type Row struct {
	FP         string
	DisplayID  string
	Sev        string
	Rule       string
	Path       string
	Line       int
	Desc       string
	Confidence string
	Secret     bool
}

type Counts struct {
	Confirmed                            int
	ConfirmedHigh, ConfirmedLow          int
	Critical, High, Medium, Low, Info    int
	Dismissed, Suppressed, Baseline      int
}

type Result struct {
	NothingStaged bool
	ScopeLabel    string
	Scanners      []string
	Phase         events.Phase
	Rows          []Row
	Counts        Counts
	DismissedIDs  []string // display ids of dismissed findings, for next hints
	Items         int      // open items after this scan's fold
}

// LastScan is the coverage header the posture view shows: the scanners,
// phase, and engine of the most recent scan (cli-spec §5 bare). Derived,
// scan-written, not log-reconstructable — the last_seen family (artefacts
// §6.4, deviation cli-spec §16.18).
type LastScan struct {
	Scope    string   `json:"scope"`
	Scanners []string `json:"scanners"`
	Phase    string   `json:"phase"`
	Engine   string   `json:"engine"`
	At       string   `json:"at"`
}

// ResolveDefaultScope picks the default scope: staged when the index is
// non-empty, else full with the caller printing the note (cli-spec §5).
func ResolveDefaultScope(ctx context.Context, r Runner) (Scope, error) {
	paths, err := stagedPaths(ctx, r)
	if err != nil {
		return 0, err
	}
	if len(paths) == 0 {
		return ScopeFull, nil
	}
	return ScopeStaged, nil
}

// ReadLastScan returns the stored coverage header, or nil before any scan.
func ReadLastScan(s *store.Store) (*LastScan, error) {
	b, err := os.ReadFile(filepath.Join(s.Cavet, "state", "last-scan.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ls LastScan
	if err := json.Unmarshal(b, &ls); err != nil {
		return nil, fmt.Errorf("state/last-scan.json: %w", err)
	}
	return &ls, nil
}

// Run performs one scan end to end.
func Run(ctx context.Context, s *store.Store, r Runner, o Options) (*Result, error) {
	if o.Actor == "" {
		o.Actor = events.ActorAgent
	}
	if o.Phase == "" {
		o.Phase = events.PhaseBuild // deviation cli-spec §16.7
	}
	if o.Context == "" {
		o.Context = events.ContextDispatch
	}
	if o.Engine == "" {
		return nil, fmt.Errorf("engine ref required on every event (artefacts §2.1)")
	}
	now := time.Now().UTC()
	fsScanners := TierScanners(o.Scope, o.Deep)

	var target string
	var cov Coverage
	var images []config.ImageEntry // Dockerfiles whose images join this scan
	label := o.Scope.String()
	switch o.Scope {
	case ScopeStaged:
		paths, err := stagedPaths(ctx, r)
		if err != nil {
			return nil, err
		}
		if len(paths) == 0 {
			return &Result{NothingStaged: true, ScopeLabel: label,
				Scanners: fsScanners, Phase: o.Phase}, nil
		}
		scanDir := r.NextScanDir()
		if err := checkoutIndex(ctx, r, scanDir); err != nil {
			return nil, err
		}
		target, cov = scanDir, Coverage{Paths: toSet(paths)}
		// The image phase joins a staged scan exactly when a configured
		// Dockerfile is among the staged paths.
		images = intersectEntries(o.Images, paths)
	case ScopeDiff:
		paths, err := diffPaths(ctx, r, o.DiffRef)
		if err != nil {
			return nil, err
		}
		scanDir := r.NextScanDir()
		if err := stageWorktree(ctx, r, o.DiffRef, scanDir); err != nil {
			return nil, err
		}
		target, cov, label = scanDir, Coverage{Paths: toSet(paths)}, "diff "+o.DiffRef
	case ScopeFull:
		target, cov = "/workspace", Coverage{AllPaths: true}
		images = o.Images // --full runs the image phase when images are configured
	case ScopeImage:
		if len(o.Images) == 0 {
			return nil, fmt.Errorf("no container images configured; run 'cavet image add <dockerfile>' or set scan.container_images")
		}
		// The image phase covers the Dockerfile locations; path-based coverage
		// stays intact (delta.go covered()).
		cov = Coverage{Paths: toSet(entryPaths(o.Images))}
		images = o.Images
	}
	scanners := fsScanners
	if len(images) > 0 {
		scanners = append(scanners, "trivy-image")
	}
	cov.Scanners = scanners

	raw := map[string][]byte{}
	if target != "" {
		var err error
		raw, err = runScanners(ctx, r, fsScanners, target)
		if err != nil {
			return nil, err
		}
	}
	var imageFindings []projection.Finding
	if len(images) > 0 {
		// staged: the image phase joined a staged scan, so coverage credits
		// index content while builds compile the working tree (image.go).
		b, fs, err := scanImages(ctx, s, r, images, o.Scope == ScopeStaged)
		if err != nil {
			return nil, err
		}
		raw["trivy-image"] = b
		imageFindings = fs
	}
	merged, err := parseAndMerge(scanners, raw, target, imageFindings)
	if err != nil {
		return nil, err
	}

	// Critical section: fold + appends + state rewrite under the lock (§14).
	rel, err := s.Lock()
	if err != nil {
		return nil, err
	}
	defer rel()
	state, err := s.LoadState()
	if err != nil {
		return nil, err
	}
	fr, err := Fold(state, merged, cov, o, now)
	if err != nil {
		return nil, err
	}
	for _, ev := range fr.Events {
		if err := s.Append(ev); err != nil {
			return nil, err
		}
	}
	state.Findings = fr.Findings
	store.AssignDisplayIDs(state.Findings)
	if err := s.WriteState(state); err != nil {
		return nil, err
	}
	if err := writeMergedReport(s, raw); err != nil {
		return nil, err
	}
	// Deep scans refresh the local rule catalogue from the opengrep SARIF we
	// already hold — version-exact, offline (spec §5.3).
	if b, ok := raw["opengrep"]; ok {
		_ = lookup.WriteRuleCatalog(lookup.CatalogPath(filepath.Join(s.Cavet, "cache", "advisories")),
			lookup.ExtractRules(b))
	}
	if ls, err := json.Marshal(LastScan{Scope: label, Scanners: scanners,
		Phase: string(o.Phase), Engine: o.Engine, At: now.UTC().Format(time.RFC3339)}); err == nil {
		_ = store.AtomicWrite(filepath.Join(s.Cavet, "state", "last-scan.json"), append(ls, '\n'))
	}
	return buildResult(merged, state, label, scanners, o), nil
}

// invocation builds each scanner's command per cli-spec §7.
func invocation(scanner, target string) []string {
	switch scanner {
	case "gitleaks":
		if target == "/workspace" {
			return []string{"gitleaks", "detect", "--source", "/workspace",
				"--report-format", "sarif", "--report-path", "/reports/gitleaks.sarif", "--exit-code", "0"}
		}
		return []string{"gitleaks", "dir", target,
			"--report-format", "sarif", "--report-path", "/reports/gitleaks.sarif", "--exit-code", "0"}
	case "trivy":
		return []string{"trivy", "fs", "--scanners", "vuln,misconfig,secret",
			"--skip-db-update", "--skip-check-update", "--offline-scan",
			"--format", "sarif", "--output", "/reports/trivy.sarif", target}
	case "trivy-image":
		// target is the container-side tar the image phase copied in; the
		// per-image ordinal rides it, so every image writes its own report
		// file (see reportPath).
		return []string{"trivy", "image", "--input", target,
			"--offline-scan", "--skip-db-update", "--skip-check-update",
			"--format", "sarif", "--output", reportPath("trivy-image", target)}
	case "opengrep":
		return []string{"opengrep", "scan", "--config", "/opt/opengrep-rules",
			"--sarif", "--output", "/reports/opengrep.sarif", target}
	}
	return nil
}

// reportPath is the container path a scanner's report lands at. trivy-image
// runs once per image, so its report name carries the image ordinal derived
// from the target tar (image-<n>.tar): /reports persists in the container
// across scans, and a shared name would let a failed exec copy out the
// previous image's or previous scan's report.
func reportPath(scanner, target string) string {
	if scanner == "trivy-image" {
		return "/reports/trivy-image-" +
			strings.TrimSuffix(strings.TrimPrefix(target, "/scan/image-"), ".tar") + ".sarif"
	}
	return "/reports/" + scanner + ".sarif"
}

func runScanners(ctx context.Context, r Runner, scanners []string, target string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, sc := range scanners {
		res, err := r.Exec(ctx, invocation(sc, target))
		if err != nil {
			return nil, err
		}
		b, cerr := r.CopyOut(ctx, reportPath(sc, target))
		// Non-zero exit without a report is the anomaly contract (§10.3). A
		// trivy-image run also fails on a non-zero exit with a report: the
		// file on disk can be a stale one from an earlier scan, and reusing
		// it would mis-attribute findings or mask the failure as clean.
		if cerr != nil || (sc == "trivy-image" && res.Code != 0) {
			return nil, fmt.Errorf("%s scan failed (exit %d): %.300s", sc, res.Code, res.Stderr)
		}
		out[sc] = b
	}
	return out, nil
}

func parseAndMerge(scanners []string, raw map[string][]byte, target string, imageFindings []projection.Finding) ([]*projection.MergedFinding, error) {
	var findings []projection.Finding
	for _, sc := range scanners {
		if sc == "trivy-image" {
			// Parsed per image in image.go with its Dockerfile location and
			// path-derived identity; re-parsing here would lose both.
			continue
		}
		fs, warns, err := projection.Parse(sc, raw[sc], target)
		if err != nil {
			return nil, err
		}
		for _, w := range warns {
			fmt.Fprintf(os.Stderr, "warning: %s\n", w)
		}
		findings = append(findings, fs...)
	}
	findings = append(findings, imageFindings...)
	return projection.Merge(findings), nil
}

// writeMergedReport concatenates the scanners' runs into one SARIF document
// for machines (artefacts §12); raw SARIF never reaches the model.
func writeMergedReport(s *store.Store, raw map[string][]byte) error {
	var docs [][]byte
	for _, b := range raw {
		docs = append(docs, b)
	}
	out, err := stitchRuns(docs)
	if err != nil {
		return err
	}
	return store.AtomicWrite(filepath.Join(s.Cavet, "reports", "latest.sarif"), append(out, '\n'))
}

// stitchRuns concatenates SARIF documents into one carrying all their runs:
// per-image trivy-image reports merge into a single scanner document this way.
func stitchRuns(docs [][]byte) ([]byte, error) {
	var runs []json.RawMessage
	for _, b := range docs {
		var doc struct {
			Runs []json.RawMessage `json:"runs"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("merging reports: %w", err)
		}
		runs = append(runs, doc.Runs...)
	}
	return json.Marshal(struct {
		Version string           `json:"version"`
		Schema  string           `json:"$schema"`
		Runs    []json.RawMessage `json:"runs"`
	}{"2.1.0", "https://json.schemastore.org/sarif-2.1.0.json", runs})
}

func buildResult(merged []*projection.MergedFinding, state *store.State, label string, scanners []string, o Options) *Result {
	res := &Result{ScopeLabel: label, Scanners: scanners, Phase: o.Phase,
		Counts: Counts{Baseline: len(state.Baseline.Fingerprints)},
		Items:  len(state.Items)}
	byFP := map[string]*store.Finding{}
	for _, f := range state.Findings {
		byFP[f.Fingerprint] = f
	}
	for _, m := range merged {
		f := byFP[m.Fingerprint]
		if f == nil {
			continue
		}
		conf := ""
		if f.Verdict != nil {
			conf = f.Verdict.Confidence
		}
		switch f.Status {
		case "open", "confirmed":
			res.Rows = append(res.Rows, Row{
				FP: f.Fingerprint, DisplayID: f.DisplayID,
				Sev: f.Severity, Rule: f.RuleID,
				Path: m.Locations[0].Path, Line: m.Locations[0].Line,
				Desc: f.Description, Confidence: conf, Secret: f.Secret,
			})
			res.Counts.Confirmed++
			switch conf {
			case "high":
				res.Counts.ConfirmedHigh++
			case "low":
				res.Counts.ConfirmedLow++
			}
			switch f.Severity {
			case "critical":
				res.Counts.Critical++
			case "high":
				res.Counts.High++
			case "medium":
				res.Counts.Medium++
			case "low":
				res.Counts.Low++
			case "info":
				res.Counts.Info++
			}
		case "dismissed":
			// Counted in the aggregate, never a table row — a dismiss must
			// visibly shrink the table (cli-spec §16.23).
			res.Counts.Dismissed++
			res.DismissedIDs = append(res.DismissedIDs, f.DisplayID)
		case "suppressed":
			res.Counts.Suppressed++
		}
	}
	return res
}

func toSet(paths []string) map[string]bool {
	m := make(map[string]bool, len(paths))
	for _, p := range paths {
		m[p] = true
	}
	return m
}

// intersectEntries keeps want's order, membership from have.
func intersectEntries(want []config.ImageEntry, have []string) []config.ImageEntry {
	set := toSet(have)
	var out []config.ImageEntry
	for _, e := range want {
		if set[e.Dockerfile] {
			out = append(out, e)
		}
	}
	return out
}

func entryPaths(es []config.ImageEntry) []string {
	paths := make([]string, 0, len(es))
	for _, e := range es {
		paths = append(paths, e.Dockerfile)
	}
	return paths
}
