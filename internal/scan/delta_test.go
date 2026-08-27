package scan

import (
	"strings"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/projection"
	"github.com/ChaosChild/cavet/internal/store"
)

var foldNow = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

var foldOpts = Options{
	Actor:  events.ActorAgent,
	Phase:  events.PhaseBuild,
	Context: events.ContextDispatch,
	Engine: "ghcr.io/x@sha256:a",
}

func fullCoverage() Coverage {
	return Coverage{Scanners: []string{"gitleaks", "trivy", "opengrep"}, AllPaths: true}
}

func mf(fp, scanner, path string, line int) *projection.MergedFinding {
	return &projection.MergedFinding{
		Fingerprint: fp, RuleID: "r", RuleKey: "r", Severity: "high",
		Description: "d", Scanner: scanner,
		Locations: []projection.Location{{Path: path, Line: line}},
	}
}

func stateWithFindings(fs ...*store.Finding) *store.State {
	st := &store.State{Findings: fs}
	for _, f := range fs {
		if f.Status == "" {
			f.Status = "open"
		}
	}
	return st
}

func eventKinds(evs []events.Event) []events.Kind {
	var out []events.Kind
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func TestFoldKnownFindingRefreshesSilently(t *testing.T) {
	fp := strings.Repeat("a1", 32)
	st := stateWithFindings(&store.Finding{Fingerprint: fp, Status: "open",
		Locations: []store.Location{{Path: "a.py", Line: 1}}})
	res, err := Fold(st, []*projection.MergedFinding{mf(fp, "opengrep", "a.py", 1)}, fullCoverage(), foldOpts, foldNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || res.Events[0].Kind != events.Surfaced {
		t.Fatalf("known fingerprint at known location: only surfaced, got %v", eventKinds(res.Events))
	}
	if !res.Findings[0].LastSeen.Equal(foldNow) {
		t.Fatal("last_seen must refresh")
	}
}

func TestFoldNewLocationEmitsDetected(t *testing.T) {
	fp := strings.Repeat("a1", 32)
	st := stateWithFindings(&store.Finding{Fingerprint: fp, Status: "open",
		Locations: []store.Location{{Path: "a.py", Line: 1}}})
	m := mf(fp, "opengrep", "a.py", 1)
	m.Locations = append(m.Locations, projection.Location{Path: "b.py", Line: 2})
	res, err := Fold(st, []*projection.MergedFinding{m}, fullCoverage(), foldOpts, foldNow)
	if err != nil {
		t.Fatal(err)
	}
	kinds := eventKinds(res.Events)
	if len(kinds) != 2 || kinds[0] != events.Detected || kinds[1] != events.Surfaced {
		t.Fatalf("new location: detected + surfaced, got %v", kinds)
	}
	if len(res.Findings[0].Locations) != 2 {
		t.Fatal("location list must grow")
	}
}

func TestFoldUnseenEmitsDetectedPerLocation(t *testing.T) {
	fp := strings.Repeat("b2", 32)
	m := mf(fp, "trivy", "req.txt", 3)
	m.Locations = append(m.Locations, projection.Location{Path: "other.txt", Line: 9})
	res, err := Fold(stateWithFindings(), []*projection.MergedFinding{m}, fullCoverage(), foldOpts, foldNow)
	if err != nil {
		t.Fatal(err)
	}
	detected := 0
	for _, e := range res.Events {
		if e.Kind == events.Detected {
			detected++
		}
	}
	if detected != 2 {
		t.Fatalf("one detected event per location (rebuild reproduces state), got %d", detected)
	}
	if len(res.Findings) != 1 || res.Findings[0].Status != "open" {
		t.Fatal("unseen finding inserted as open")
	}
}

func TestFoldBaselineOnlyInsertsSilently(t *testing.T) {
	fp := strings.Repeat("c3", 32)
	st := stateWithFindings()
	st.Baseline.Fingerprints = []string{fp}
	res, err := Fold(st, []*projection.MergedFinding{mf(fp, "opengrep", "a.py", 1)}, fullCoverage(), foldOpts, foldNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Events {
		if e.Kind == events.Detected {
			t.Fatal("baseline findings' detections predate us; no detected event")
		}
	}
	if len(res.Findings) != 1 || !res.Findings[0].InBaseline {
		t.Fatal("inserted with in_baseline=true")
	}
}

func TestFoldRemediationGating(t *testing.T) {
	fpOG := strings.Repeat("d4", 32)
	fpGL := strings.Repeat("e5", 32)
	st := stateWithFindings(
		&store.Finding{Fingerprint: fpOG, OriginatingScanner: "opengrep",
			Locations: []store.Location{{Path: "deep.py", Line: 1}}},
		&store.Finding{Fingerprint: fpGL, OriginatingScanner: "gitleaks",
			Locations: []store.Location{{Path: "secret.py", Line: 1}}},
	)
	// Fast scan: gitleaks+trivy ran, only secret.py in scope; neither finding
	// appears in results.
	cov := Coverage{Scanners: []string{"gitleaks", "trivy"}, Paths: map[string]bool{"secret.py": true}}
	res, err := Fold(st, nil, cov, foldOpts, foldNow)
	if err != nil {
		t.Fatal(err)
	}
	kinds := eventKinds(res.Events)
	if len(kinds) != 1 || kinds[0] != events.Remediated {
		t.Fatalf("only the covered gitleaks finding remediates, got %v", kinds)
	}
	if res.Findings[0].Fingerprint != fpOG {
		t.Fatalf("uncovered-origin finding must be retained, got %s", res.Findings[0].Fingerprint)
	}

	// Full scan covering both: both remidiate.
	res, err = Fold(st, nil, fullCoverage(), foldOpts, foldNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatal("full coverage + absence remidiates everything")
	}
}

func TestFoldSurfacesOnlyActionableRows(t *testing.T) {
	fpOpen := strings.Repeat("f6", 32)
	fpDismissed := strings.Repeat("07", 32)
	st := stateWithFindings(
		&store.Finding{Fingerprint: fpOpen, Status: "open"},
		&store.Finding{Fingerprint: fpDismissed, Status: "dismissed"},
	)
	res, err := Fold(st, []*projection.MergedFinding{
		mf(fpOpen, "gitleaks", "a.py", 1),
		mf(fpDismissed, "gitleaks", "b.py", 1),
	}, fullCoverage(), foldOpts, foldNow)
	if err != nil {
		t.Fatal(err)
	}
	surfaced := 0
	for _, e := range res.Events {
		if e.Kind == events.Surfaced {
			surfaced++
			if e.Fingerprint != fpOpen {
				t.Fatal("surfaced must carry the actionable finding's fingerprint")
			}
		}
	}
	if surfaced != 1 {
		t.Fatalf("dismissed findings are never surfaced, got %d", surfaced)
	}
}
