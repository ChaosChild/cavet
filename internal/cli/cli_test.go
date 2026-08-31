package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/config"
	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/scan"
	"github.com/ChaosChild/cavet/internal/store"
)

func TestHintsMechanical(t *testing.T) {
	row := func(id string) scan.Row { return scan.Row{FP: "f" + id, DisplayID: id} }
	if got := hints(&scan.Result{}); len(got) != 0 {
		t.Fatalf("no rows, no baseline: no hints, got %v", got)
	}
	if got := hints(&scan.Result{Counts: scan.Counts{Baseline: 347}}); len(got) != 1 || got[0] != "cavet debt" {
		t.Fatalf("debt hint when nothing better, got %v", got)
	}
	got := hints(&scan.Result{Rows: []scan.Row{row("a3f9c2"), row("7b1e04"), row("c0ffee")}})
	want := []string{"cavet finding a3f9c2 --full", "cavet log --fingerprint 7b1e04"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("hints: got %v want %v", got, want)
	}
	got = hints(&scan.Result{Rows: []scan.Row{row("a3f9c2")}})
	if got[1] != "cavet log --fingerprint a3f9c2" {
		t.Fatalf("single row reuses its id for the log hint: %v", got)
	}
}

// Fix 5: hints derive from result state — post-triage output must differ.
func TestHintsStateDerived(t *testing.T) {
	row := func(id string) scan.Row { return scan.Row{FP: "f" + id, DisplayID: id} }

	// Dismissed findings redirect the log hint to their audit trail.
	got := hints(&scan.Result{Rows: []scan.Row{row("a3f9c2")}, DismissedIDs: []string{"0c44f7"}})
	want := []string{"cavet finding a3f9c2 --full", "cavet log --fingerprint 0c44f7"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dismissed must earn the log hint, got %v", got)
	}

	// Open items earn a `cavet items` hint.
	got = hints(&scan.Result{Items: 1})
	if len(got) != 1 || got[0] != "cavet items" {
		t.Fatalf("open items must be hinted, got %v", got)
	}

	// A triaged secret takes the finding hint.
	secret := scan.Row{FP: "fs", DisplayID: "5ec123", Secret: true, Confidence: "high"}
	got = hints(&scan.Result{Rows: []scan.Row{row("a3f9c2"), secret}})
	if got[0] != "cavet finding 5ec123 --full" {
		t.Fatalf("confirmed secret must be the finding hint, got %v", got)
	}
	// Untriaged secrets do not outrank the top row.
	got = hints(&scan.Result{Rows: []scan.Row{row("a3f9c2"), {FP: "fs", DisplayID: "5ec123", Secret: true}}})
	if got[0] != "cavet finding a3f9c2 --full" {
		t.Fatalf("untriaged secret must not jump the queue, got %v", got)
	}

	// Cap at three, deterministic order: finding, items, log.
	got = hints(&scan.Result{Rows: []scan.Row{row("a3f9c2"), row("7b1e04")}, Items: 2, DismissedIDs: []string{"0c44f7"}})
	want = []string{"cavet finding a3f9c2 --full", "cavet items", "cavet log --fingerprint 0c44f7"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("hints must cap at three in fixed order, got %v", got)
	}
}

// Fix 7: the initialised root is discovered upward from cwd, git-style; a
// missing root names the walk in the error.
func TestRepoRootWalksUp(t *testing.T) {
	root := t.TempDir()
	if _, err := store.Init(root); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "pkg", "deep")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(nested)
	got, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(filepath.Clean(got), filepath.Clean(root)) {
		t.Fatalf("walk must find the initialised root: got %q want %q", got, root)
	}
	if _, err := openStore(); err != nil {
		t.Fatalf("commands must work from a nested subdir: %v", err)
	}

	t.Chdir(t.TempDir())
	_, err = repoRoot()
	if err == nil || !strings.Contains(err.Error(), "or any parent") {
		t.Fatalf("error must name the upward walk, got %v", err)
	}
}

func TestParseSources(t *testing.T) {
	got, err := parseSources([]string{"CVE-2021-44228=https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "GHSA-x=https://g"})
	if err != nil || len(got) != 2 || got[0].ID != "CVE-2021-44228" {
		t.Fatalf("got %+v err %v", got, err)
	}
	if _, err := parseSources([]string{"no-url"}); err == nil {
		t.Fatal("malformed source must fail")
	}
}

func TestResolveFindingPrefix(t *testing.T) {
	st := &store.State{Findings: []*store.Finding{
		{Fingerprint: "a3f9c2" + "0000", DisplayID: "a3f9c2"},
		{Fingerprint: "7b1e04" + "0000", DisplayID: "7b1e04"},
	}}
	f, err := resolveFinding(st, "a3f9")
	if err != nil || f.DisplayID != "a3f9c2" {
		t.Fatalf("prefix must resolve: %v %v", f, err)
	}
	// Both display ids share no prefix here; force ambiguity via full-hash prefix:
	st.Findings[1].DisplayID = "a3f9zz"
	if _, err := resolveFinding(st, "a3f9"); err == nil {
		t.Fatal("ambiguous prefix must fail")
	}
	if _, err := resolveFinding(st, "ffffff"); err == nil {
		t.Fatal("unknown id must fail")
	}
}

// ldflags-set versions map to minor-pinned engine tags; dev/devel builds keep
// the rolling variant-only tag (cli-spec §16.19, engine-spec §1 deviation 8).
func TestEngineRefVersionTags(t *testing.T) {
	origVersion, origImg := version, os.Getenv("CAVET_ENGINE_IMAGE")
	os.Unsetenv("CAVET_ENGINE_IMAGE")
	t.Cleanup(func() {
		version = origVersion
		if origImg != "" {
			os.Setenv("CAVET_ENGINE_IMAGE", origImg)
		}
	})
	cases := []struct{ version, variant, want string }{
		{"0.1.0", "core", "ghcr.io/chaoschild/cavet-engine:0.1-core"},
		{"v1.2.3-rc1", "full", "ghcr.io/chaoschild/cavet-engine:1.2-full"},
		{"dev", "core", "ghcr.io/chaoschild/cavet-engine:core"},
		{"devel", "full", "ghcr.io/chaoschild/cavet-engine:full"},
		// Local go builds stamp a pseudo-version into the build info; they
		// must keep the rolling tag, not a bogus 0.0-<variant> pin.
		{"0.0.0-20260831115634-1fe5bfa8e191+dirty", "core", "ghcr.io/chaoschild/cavet-engine:core"},
	}
	for _, c := range cases {
		version = c.version
		cfg := config.Default()
		cfg.Engine.Variant = c.variant
		got := engineRef(cfg)
		if got != c.want {
			t.Errorf("version %q variant %q: got %q want %q", c.version, c.variant, got, c.want)
		}
	}
	// Digest pin and image override are unchanged by the tag derivation.
	version = "0.1.0"
	cfg := config.Default()
	cfg.Engine.Digest = "sha256:abcd"
	if got := engineRef(cfg); got != "ghcr.io/chaoschild/cavet-engine:0.1-core@sha256:abcd" {
		t.Errorf("digest pin: got %q", got)
	}
	os.Setenv("CAVET_ENGINE_IMAGE", "localhost/cavet-engine:dev")
	if got := engineRef(config.Default()); got != "localhost/cavet-engine:dev" {
		t.Errorf("CAVET_ENGINE_IMAGE must override tag derivation, got %q", got)
	}
}

// resolveVersion: ldflags value wins, then the build-info module version
// (go install builds), then "dev". Test binaries have (devel)/empty build
// info, so the fallback chain ends at "dev" here.
func TestResolveVersion(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })
	for in, want := range map[string]string{
		"9.9.9": "9.9.9",
		"v8.8.8": "8.8.8",
	} {
		version = in
		if got := resolveVersion(); got != want {
			t.Errorf("set %q: got %q want %q", in, got, want)
		}
	}
	for _, in := range []string{"dev", "", "(devel)"} {
		version = in
		if got := resolveVersion(); got != "dev" {
			t.Errorf("unset %q: got %q want dev (test build info is devel/empty)", in, got)
		}
	}
}

func TestShortEngine(t *testing.T) {
	if got := shortEngine("ghcr.io/x/e@sha256:4f2a9b8c"); got != "ghcr.io/x/e@sha256:4f2a…" {
		t.Fatalf("got %q", got)
	}
	if got := shortEngine("cavet-engine:dev"); got != "cavet-engine:dev" {
		t.Fatalf("bare ref passes through, got %q", got)
	}
}

func TestExcerpt(t *testing.T) {
	ev, err := events.NewDeferred(time.Now().UTC(), events.ActorOperator, events.PhaseBuild,
		"ghcr.io/x@sha256:a", "ab"+strings.Repeat("0", 62), "after the release")
	if err != nil {
		t.Fatal(err)
	}
	if got := excerpt(ev); got != "after the release" {
		t.Fatalf("got %q", got)
	}
}
