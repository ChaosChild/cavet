package store

import (
	"strings"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
)

func fpC() string { return strings.Repeat("c3", 32) }

// synthLog builds a two-scan log: three detections in scan 1, a dismissal, a
// confirmation, then scan 2 remediates one finding and surfaces another.
func synthLog(s *Store, base time.Time) error {
	const eng = "ghcr.io/chaoschild/cavet-engine:0.2-core"
	must := func(ev events.Event, err error) error {
		if err != nil {
			return err
		}
		return s.Append(ev)
	}
	det := func(ts time.Time, fp string, sev events.Severity, rule, scanner, path string) error {
		return must(events.NewDetected(ts, events.ActorAgent, events.PhaseBuild, eng, fp,
			events.DetectedData{Rule: rule, Severity: sev, Path: path, Line: 1, Scanner: scanner}))
	}
	t1, t2, t3, t4 := base.Add(-48*time.Hour), base.Add(-47*time.Hour), base.Add(-46*time.Hour), base.Add(-24*time.Hour)
	if err := det(t1, fpA(), events.SevCritical, "G101", "gitleaks", "a.go"); err != nil {
		return err
	}
	if err := det(t1, fpB(), events.SevHigh, "CVE-1", "trivy", "go.sum"); err != nil {
		return err
	}
	if err := det(t1, fpC(), events.SevMedium, "go.err", "opengrep", "b.go"); err != nil {
		return err
	}
	if err := must(events.NewSurfaced(t1, events.ActorAgent, events.PhaseBuild, eng, fpA(),
		events.SurfacedData{Context: events.ContextPosture})); err != nil {
		return err
	}
	if err := must(events.NewTriaged(t2, events.ActorOperator, events.PhaseBuild, eng, fpA(),
		events.TriagedData{Verdict: events.VerdictDismissed, Confidence: events.ConfidenceHigh,
			Reason: "test fixture"})); err != nil {
		return err
	}
	if err := must(events.NewTriaged(t3, events.ActorOperator, events.PhaseBuild, eng, fpB(),
		events.TriagedData{Verdict: events.VerdictConfirmed, Confidence: events.ConfidenceLow,
			Reason: "real"})); err != nil {
		return err
	}
	if err := must(events.NewRemediated(t4, events.ActorAgent, events.PhaseBuild, eng, fpC(), "fixed")); err != nil {
		return err
	}
	return must(events.NewSurfaced(t4, events.ActorAgent, events.PhaseBuild, eng, fpB(),
		events.SurfacedData{Context: events.ContextPosture}))
}

func TestComputeMetricsFromSyntheticLog(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Hour)
	if err := synthLog(s, base); err != nil {
		t.Fatal(err)
	}
	log, err := s.ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ComputeMetrics(log, "cursor")
	if err != nil {
		t.Fatal(err)
	}

	counts := map[string]int{}
	for _, fr := range doc.Flow {
		counts[fr.Kind]++
	}
	want := map[string]int{"new": 3, "dismissed": 1, "fixed": 1, "deferred": 0}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("flow %s = %d, want %d", k, counts[k], v)
		}
	}

	// Actor split and resolve lag: the one remediation is by the agent, 24h
	// after detection (t4 - t1).
	if len(doc.Resolve) != 1 {
		t.Fatalf("resolve recs = %d, want 1", len(doc.Resolve))
	}
	if doc.Resolve[0].Actor != "agent" || doc.Resolve[0].Hours != 24 {
		t.Errorf("resolve = %+v, want agent/24h", doc.Resolve[0])
	}

	// Triage lags: 1h (dismissed) and 2h (confirmed).
	lags := map[float64]bool{}
	for _, l := range doc.Triage {
		lags[l.Hours] = true
	}
	if !lags[1] || !lags[2] {
		t.Errorf("triage lags = %v, want 1h and 2h", lags)
	}

	// Trend: previous snapshot is after scan 1 (3 actionable), current is 1
	// (the confirmed high).
	if doc.Trend.Current["total"] != 1 || doc.Trend.Current["high"] != 1 {
		t.Errorf("trend current = %v", doc.Trend.Current)
	}
	if doc.Trend.Previous == nil || doc.Trend.Previous["total"] != 3 ||
		doc.Trend.Previous["critical"] != 1 || doc.Trend.Previous["medium"] != 1 {
		t.Errorf("trend previous = %+v, want 3 total / 1 critical / 1 medium", doc.Trend.Previous)
	}
	if len(doc.ScanTimes) != 2 {
		t.Errorf("scan times = %d, want 2", len(doc.ScanTimes))
	}

	// Remediated records (serve-task-2): the one remediation captures the row
	// shape with detection and remediation timestamps.
	if len(doc.Remediated) != 1 {
		t.Fatalf("remediated recs = %d, want 1", len(doc.Remediated))
	}
	rec := doc.Remediated[0]
	t1, t4 := base.Add(-48*time.Hour), base.Add(-24*time.Hour)
	if rec.Fingerprint != fpC() || rec.Rule != "go.err" || rec.Severity != string(events.SevMedium) ||
		rec.Scanner != "opengrep" || !rec.DetectedAt.Equal(t1) || !rec.RemediatedAt.Equal(t4) {
		t.Errorf("remediated rec = %+v, want fpC/go.err/medium/opengrep t1..t4", rec)
	}
	// The remediated event's reason and actor are the resolved rows' verdict.
	if rec.Reason != "fixed" || rec.Actor != "agent" {
		t.Errorf("remediated rec verdict = %q by %q, want fixed by agent", rec.Reason, rec.Actor)
	}
}

// The remediated record snapshots the finding's locations at remediation time:
// a re-detection that adds a location lands in the resolved row, and the
// locations schema bump forces older caches to recompute.
func TestComputeMetricsRemediatedCapturesLocations(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Hour)
	const eng = "ghcr.io/chaoschild/cavet-engine:0.2-core"
	app := func(ev events.Event, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	app(events.NewDetected(base.Add(-48*time.Hour), events.ActorAgent, events.PhaseBuild, eng, fpC(),
		events.DetectedData{Rule: "go.err", Severity: events.SevMedium, Path: "b.go", Line: 1, Scanner: "opengrep"}))
	app(events.NewDetected(base.Add(-47*time.Hour), events.ActorAgent, events.PhaseBuild, eng, fpC(),
		events.DetectedData{Rule: "go.err", Severity: events.SevMedium, Path: "b.go", Line: 7, Scanner: "opengrep"}))
	app(events.NewRemediated(base.Add(-24*time.Hour), events.ActorAgent, events.PhaseBuild, eng, fpC(), "fixed"))

	log, err := s.ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ComputeMetrics(log, "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Remediated) != 1 {
		t.Fatalf("remediated recs = %d, want 1", len(doc.Remediated))
	}
	locs := doc.Remediated[0].Locations
	if len(locs) != 2 || locs[0] != (Location{Path: "b.go", Line: 1}) ||
		locs[1] != (Location{Path: "b.go", Line: 7}) {
		t.Errorf("locations = %v, want b.go:1 and b.go:7", locs)
	}

	// The schema bump: a cache written by the previous version must recompute.
	if err := s.RefreshMetrics(); err != nil {
		t.Fatal(err)
	}
	stored, err := s.LoadMetrics()
	if err != nil || stored == nil {
		t.Fatal(err)
	}
	stored.SchemaVersion = MetricsCacheVersion - 1
	if err := s.WriteMetrics(stored); err != nil {
		t.Fatal(err)
	}
	if !s.MetricsStale() {
		t.Fatal("pre-locations schema must mark the cache stale")
	}
}

// A v1 cache (before the remediated records) must be stale so serve start
// recomputes it into the v2 shape.
func TestMetricsV1SchemaIsStale(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Hour)
	if err := synthLog(s, base); err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshMetrics(); err != nil {
		t.Fatal(err)
	}
	doc, err := s.LoadMetrics()
	if err != nil || doc == nil {
		t.Fatal(err)
	}
	doc.SchemaVersion = MetricsCacheVersion - 1
	if err := s.WriteMetrics(doc); err != nil {
		t.Fatal(err)
	}
	if !s.MetricsStale() {
		t.Fatal("v1 schema must mark the cache stale")
	}
}

// Stale verdict events (triaged/suppressed/deferred) for fingerprints the
// replay never saw – e.g. findings remediated and re-baselined out of an
// earlier log segment – must not block the metrics cache: they cannot affect
// any aggregate, so ComputeMetrics skips them and still succeeds.
func TestComputeMetricsToleratesStaleVerdicts(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Hour)
	if err := synthLog(s, base); err != nil {
		t.Fatal(err)
	}
	ghost := strings.Repeat("9f", 32)
	ts := base.Add(-10 * time.Hour)
	app := func(ev events.Event, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	app(events.NewTriaged(ts, events.ActorOperator, events.PhaseBuild, "eng", ghost,
		events.TriagedData{Verdict: events.VerdictConfirmed, Confidence: events.ConfidenceHigh, Reason: "stale"}))
	app(events.NewSuppressed(ts.Add(time.Minute), events.ActorOperator, events.PhaseBuild, "eng", ghost, "stale"))
	app(events.NewDeferred(ts.Add(2*time.Minute), events.ActorOperator, events.PhaseBuild, "eng", ghost, "stale"))
	app(events.NewRemediated(ts.Add(3*time.Minute), events.ActorAgent, events.PhaseBuild, "eng", ghost, "stale"))

	log, err := s.ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ComputeMetrics(log, "cursor")
	if err != nil {
		t.Fatalf("stale verdicts must not error the fold: %v", err)
	}
	// The ghost events fold to nothing: same aggregates as without them.
	counts := map[string]int{}
	for _, fr := range doc.Flow {
		counts[fr.Kind]++
	}
	if counts["new"] != 3 || counts["dismissed"] != 1 || counts["fixed"] != 1 || counts["deferred"] != 0 {
		t.Errorf("flow = %v, ghost events leaked in", counts)
	}
	if doc.Trend.Current["total"] != 1 || doc.Trend.Current["high"] != 1 {
		t.Errorf("trend current = %v", doc.Trend.Current)
	}
	if len(doc.Triage) != 2 || len(doc.Resolve) != 1 {
		t.Errorf("triage %d resolve %d, want 2 and 1", len(doc.Triage), len(doc.Resolve))
	}
	if len(doc.Remediated) != 1 {
		t.Errorf("remediated recs = %d, want 1 (ghost remediation skipped)", len(doc.Remediated))
	}
}

func TestMetricsStalenessAndRefresh(t *testing.T) {
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Hour)
	if err := synthLog(s, base); err != nil {
		t.Fatal(err)
	}
	if !s.MetricsStale() {
		t.Fatal("absent metrics.json must be stale")
	}
	if err := s.RefreshMetrics(); err != nil {
		t.Fatal(err)
	}
	if s.MetricsStale() {
		t.Fatal("fresh metrics.json must not be stale")
	}
	doc, err := s.LoadMetrics()
	if err != nil || doc == nil {
		t.Fatalf("load after refresh: %v %v", doc, err)
	}
	if doc.SchemaVersion != MetricsCacheVersion || doc.Cursor == "" {
		t.Errorf("doc header = %+v", doc)
	}

	// A log append moves the cursor: stale again.
	ev, err := events.NewDeferred(base.Add(-12*time.Hour), events.ActorOperator, events.PhaseBuild,
		"eng", fpB(), "waiting on release")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ev); err != nil {
		t.Fatal(err)
	}
	if !s.MetricsStale() {
		t.Fatal("cursor mismatch must mark the cache stale")
	}

	// A schema-version mismatch is stale even with a matching cursor.
	if err := s.RefreshMetrics(); err != nil {
		t.Fatal(err)
	}
	doc.SchemaVersion = MetricsCacheVersion + 1
	if err := s.WriteMetrics(doc); err != nil {
		t.Fatal(err)
	}
	if !s.MetricsStale() {
		t.Fatal("schema mismatch must mark the cache stale")
	}
}
