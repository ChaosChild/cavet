package cli

import (
	"strings"
	"testing"
	"time"

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
