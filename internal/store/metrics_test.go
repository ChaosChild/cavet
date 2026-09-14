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
