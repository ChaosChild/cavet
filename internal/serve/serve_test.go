package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/store"
)

func fpA() string { return strings.Repeat("a1", 32) }
func fpB() string { return strings.Repeat("b2", 32) }
func fpC() string { return strings.Repeat("c3", 32) }

// fixture builds a temp .cavet with a two-scan log replayed into state, a
// baseline, a last-scan header, and a fresh metrics cache.
func fixture(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const eng = "ghcr.io/chaoschild/cavet-engine:0.2-core@sha256:4f2a9b"
	base := time.Now().UTC().Truncate(time.Hour)
	t1, t2, t3, t4 := base.Add(-48*time.Hour), base.Add(-47*time.Hour), base.Add(-46*time.Hour), base.Add(-24*time.Hour)
	appendEv := func(ev events.Event, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	appendEv(events.NewDetected(t1, events.ActorAgent, events.PhaseBuild, eng, fpA(),
		events.DetectedData{Rule: "G101", Severity: events.SevCritical, Path: "a.go", Line: 3, Scanner: "gitleaks"}))
	appendEv(events.NewDetected(t1, events.ActorAgent, events.PhaseBuild, eng, fpB(),
		events.DetectedData{Rule: "CVE-1", Severity: events.SevHigh, Path: "go.sum", Line: 9, Scanner: "trivy"}))
	appendEv(events.NewDetected(t1, events.ActorAgent, events.PhaseBuild, eng, fpC(),
		events.DetectedData{Rule: "go.err", Severity: events.SevMedium, Path: "b.go", Line: 1, Scanner: "opengrep"}))
	appendEv(events.NewSurfaced(t1, events.ActorAgent, events.PhaseBuild, eng, fpA(),
		events.SurfacedData{Context: events.ContextPosture}))
	appendEv(events.NewTriaged(t2, events.ActorOperator, events.PhaseBuild, eng, fpA(),
		events.TriagedData{Verdict: events.VerdictDismissed, Confidence: events.ConfidenceHigh, Reason: "fixture"}))
	appendEv(events.NewTriaged(t3, events.ActorOperator, events.PhaseBuild, eng, fpB(),
		events.TriagedData{Verdict: events.VerdictConfirmed, Confidence: events.ConfidenceLow, Reason: "real"}))
	appendEv(events.NewRemediated(t4, events.ActorAgent, events.PhaseBuild, eng, fpC(), "fixed upstream"))
	appendEv(events.NewSurfaced(t4, events.ActorAgent, events.PhaseBuild, eng, fpB(),
		events.SurfacedData{Context: events.ContextPosture}))
	appendEv(events.NewRaised(t2, events.ActorAgent, events.PhaseDesign, eng,
		events.RaisedData{Kind: events.ItemDesign, Question: "bind policy?"}))

	if _, err := s.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteBaseline(store.Baseline{EngineDigest: eng,
		CreatedAt: t1, Fingerprints: []string{fpA()}}); err != nil {
		t.Fatal(err)
	}
	// Re-run rebuild so baseline membership loads; then the metrics cache.
	if _, err := s.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshMetrics(); err != nil {
		t.Fatal(err)
	}
	lastScan := `{"scope":"full","scanners":["gitleaks","trivy","opengrep"],"phase":"build","engine":"` +
		eng + `","at":"` + t4.Format(time.RFC3339) + `"}` + "\n"
	if err := os.WriteFile(filepath.Join(s.Cavet, "state", "last-scan.json"), []byte(lastScan), 0o644); err != nil {
		t.Fatal(err)
	}
	return s
}

func getJSON(t *testing.T, h http.Handler, path string, out any) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s: bad JSON %q: %v", path, rec.Body.String(), err)
		}
	}
	return rec.Code
}

func TestOverview(t *testing.T) {
	h := New(fixture(t)).Handler()
	var o struct {
		Repo      string                `json:"repo"`
		Engine    string                `json:"engine"`
		Open      map[string]int        `json:"open"`
		Trend     map[string]int        `json:"trend"`
		Oldest    map[string]*time.Time `json:"oldest"`
		Baseline  int                   `json:"baseline"`
		OpenItems int                   `json:"open_items"`
		Scanners  []string              `json:"scanners"`
		LastScan  *struct {
			Scope string `json:"scope"`
		} `json:"last_scan"`
	}
	if code := getJSON(t, h, "/api/overview", &o); code != http.StatusOK {
		t.Fatalf("overview status %d", code)
	}
	// Actionable: only the confirmed high remains (A dismissed, C remediated).
	if o.Open["total"] != 1 || o.Open["high"] != 1 || o.Open["critical"] != 0 {
		t.Errorf("open = %v", o.Open)
	}
	// Trend vs the snapshot after scan 1 (3 actionable): total -2.
	if o.Trend["total"] != -2 || o.Trend["critical"] != -1 || o.Trend["medium"] != -1 || o.Trend["high"] != 0 {
		t.Errorf("trend = %v", o.Trend)
	}
	if o.Baseline != 1 || o.OpenItems != 1 {
		t.Errorf("baseline %d items %d", o.Baseline, o.OpenItems)
	}
	if len(o.Scanners) != 3 || o.LastScan == nil || o.LastScan.Scope != "full" {
		t.Errorf("scanners %v last_scan %+v", o.Scanners, o.LastScan)
	}
	if !strings.Contains(o.Engine, "sha256:4f2a…") {
		t.Errorf("engine = %q", o.Engine)
	}
	if o.Oldest["high"] == nil {
		t.Errorf("oldest high missing: %v", o.Oldest)
	}
}

// An unexpected severity must not add a stray key to open or oldest; the
// finding still counts toward total (api.go overview guard).
func TestOverviewUnknownSeverityNoStrayKeys(t *testing.T) {
	s := fixture(t)
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	st.Findings = append(st.Findings, &store.Finding{
		Fingerprint: strings.Repeat("d4", 32), Severity: "catastrophic",
		Status: "open", DetectedAt: time.Now().UTC(), LastSeen: time.Now().UTC(),
	})
	if err := s.WriteState(st); err != nil {
		t.Fatal(err)
	}
	var o struct {
		Open   map[string]int        `json:"open"`
		Oldest map[string]*time.Time `json:"oldest"`
	}
	if code := getJSON(t, New(s).Handler(), "/api/overview", &o); code != http.StatusOK {
		t.Fatalf("overview status %d", code)
	}
	if o.Open["total"] != 2 || o.Open["high"] != 1 {
		t.Errorf("open = %v", o.Open)
	}
	if _, ok := o.Open["catastrophic"]; ok {
		t.Errorf("stray open key: %v", o.Open)
	}
	if _, ok := o.Oldest["catastrophic"]; ok {
		t.Errorf("stray oldest key: %v", o.Oldest)
	}
}

func TestFindingsFilteringAndPagination(t *testing.T) {
	h := New(fixture(t)).Handler()
	var all struct {
		Rows  []map[string]any `json:"rows"`
		Total int              `json:"total"`
		Pages int              `json:"pages"`
		Page  int              `json:"page"`
	}
	getJSON(t, h, "/api/findings", &all)
	if all.Total != 2 { // dismissed A + confirmed B
		t.Fatalf("total = %d, want 2", all.Total)
	}
	// Sorted by severity: critical first.
	if all.Rows[0]["severity"] != "critical" || all.Rows[1]["severity"] != "high" {
		t.Errorf("order = %v %v", all.Rows[0]["severity"], all.Rows[1]["severity"])
	}

	var sev struct{ Total int }
	getJSON(t, h, "/api/findings?severity=critical", &sev)
	if sev.Total != 1 {
		t.Errorf("severity filter total = %d", sev.Total)
	}
	var sc struct{ Total int }
	getJSON(t, h, "/api/findings?scanner=gitleaks", &sc)
	if sc.Total != 1 {
		t.Errorf("scanner filter total = %d", sc.Total)
	}
	var st struct{ Total int }
	getJSON(t, h, "/api/findings?status=dismissed", &st)
	if st.Total != 1 {
		t.Errorf("status filter total = %d", st.Total)
	}

	var page2 struct {
		Rows  []map[string]any `json:"rows"`
		Total int              `json:"total"`
		Pages int              `json:"pages"`
		Page  int              `json:"page"`
	}
	getJSON(t, h, "/api/findings?per_page=1&page=2", &page2)
	if page2.Pages != 2 || page2.Page != 2 || len(page2.Rows) != 1 {
		t.Errorf("pagination = %+v", page2)
	}
	// Out-of-range page clamps to the last page.
	getJSON(t, h, "/api/findings?per_page=1&page=9", &page2)
	if page2.Page != 2 {
		t.Errorf("clamped page = %d", page2.Page)
	}
}

func TestFindingDetailHistory(t *testing.T) {
	s := fixture(t)
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, f := range st.Findings {
		if f.Fingerprint == fpA() {
			id = f.DisplayID
		}
	}
	if id == "" {
		t.Fatal("finding A missing from state")
	}
	h := New(s).Handler()
	var d struct {
		Finding struct {
			Fingerprint string `json:"fingerprint"`
			Status      string `json:"status"`
		} `json:"finding"`
		History []struct {
			Kind string    `json:"kind"`
			TS   time.Time `json:"ts"`
		} `json:"history"`
	}
	if code := getJSON(t, h, "/api/findings/"+id, &d); code != http.StatusOK {
		t.Fatalf("detail status %d", code)
	}
	if d.Finding.Fingerprint != fpA() || d.Finding.Status != "dismissed" {
		t.Errorf("finding = %+v", d.Finding)
	}
	if len(d.History) != 3 { // detected, surfaced, triaged
		t.Fatalf("history = %d events, want 3: %+v", len(d.History), d.History)
	}
	for i := 1; i < len(d.History); i++ {
		if d.History[i].TS.Before(d.History[i-1].TS) {
			t.Error("history not chronological")
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/findings/deadbeef", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown id status = %d", rec.Code)
	}
}

// Bucket math (serve-task-2): the final bucket is the current partial period,
// so the last label reads "now" and the one before it counts one whole period
// back; an event dated now lands in that final bucket.
func TestMetricsBucketsEndAtCurrentPeriod(t *testing.T) {
	now := time.Now().UTC()
	for period, n := range bucketCounts {
		starts := bucketStarts(now, period, n)
		if len(starts) != n {
			t.Fatalf("%s: %d starts, want %d", period, len(starts), n)
		}
		if !starts[n-1].Equal(periodStart(now, period)) {
			t.Errorf("%s: last bucket starts %v, want the current partial period %v",
				period, starts[n-1], periodStart(now, period))
		}
		if got := bucketOf(now, starts); got != n-1 {
			t.Errorf("%s: now lands in bucket %d, want %d", period, got, n-1)
		}
	}
	labels := metricLabels("weeks", 38)
	if labels[len(labels)-1] != "now" || labels[len(labels)-2] != "-1w" || labels[0] != "-37w" {
		t.Errorf("labels = %v…%v, want -37w…-1w,now", labels[0], labels[len(labels)-1])
	}
	var m struct {
		Count  int              `json:"count"`
		Labels []string         `json:"labels"`
		Flow   map[string][]int `json:"flow"`
	}
	if code := getJSON(t, New(fixture(t)).Handler(), "/api/metrics?period=weeks", &m); code != http.StatusOK {
		t.Fatalf("metrics status %d", code)
	}
	if m.Labels == nil || len(m.Labels) != m.Count || len(m.Flow["new"]) != m.Count {
		t.Errorf("series lengths: labels %d flow %d count %d", len(m.Labels), len(m.Flow["new"]), m.Count)
	}
	if m.Labels[len(m.Labels)-1] != "now" {
		t.Errorf("last label = %q, want now", m.Labels[len(m.Labels)-1])
	}
}

// Resolved rows come from the metrics cache (state drops remediated findings);
// the detail endpoint resolves the fingerprint the row carries.
func TestFindingsResolvedAndAll(t *testing.T) {
	h := New(fixture(t)).Handler()
	var res struct {
		Rows  []map[string]any `json:"rows"`
		Total int              `json:"total"`
	}
	if code := getJSON(t, h, "/api/findings?status=resolved", &res); code != http.StatusOK {
		t.Fatalf("resolved status %d", code)
	}
	if res.Total != 1 || len(res.Rows) != 1 {
		t.Fatalf("resolved total = %d rows %d, want 1/1", res.Total, len(res.Rows))
	}
	row := res.Rows[0]
	if row["id"] != fpC() || row["status"] != "resolved" || row["rule"] != "go.err" ||
		row["scanner"] != "opengrep" || row["severity"] != "medium" {
		t.Errorf("resolved row = %v", row)
	}
	// Resolved rows carry the remediated event's reason and actor as the verdict.
	if row["verdict"] != "fixed upstream" || row["verdict_by"] != "agent" {
		t.Errorf("resolved row verdict = %v by %v, want \"fixed upstream\" by agent",
			row["verdict"], row["verdict_by"])
	}
	// Resolved rows carry the locations the replay captured.
	if locs, ok := row["locations"].([]any); !ok || len(locs) != 1 {
		t.Errorf("resolved row locations = %v, want one entry", row["locations"])
	}

	var all struct {
		Rows []struct {
			ID       string    `json:"id"`
			Status   string    `json:"status"`
			LastSeen time.Time `json:"last_seen"`
		} `json:"rows"`
		Total int `json:"total"`
	}
	if code := getJSON(t, h, "/api/findings?status=all&per_page=100", &all); code != http.StatusOK {
		t.Fatalf("all status %d", code)
	}
	// Current findings of every status (dismissed A, confirmed B) plus the
	// resolved row, ordered by most recent activity descending.
	if all.Total != 3 {
		t.Fatalf("all total = %d, want 3", all.Total)
	}
	statuses := map[string]bool{}
	for i, r := range all.Rows {
		statuses[r.Status] = true
		if i > 0 && r.LastSeen.After(all.Rows[i-1].LastSeen) {
			t.Errorf("row %d more recent than row %d: %v > %v", i, i-1, r.LastSeen, all.Rows[i-1].LastSeen)
		}
	}
	if !statuses["dismissed"] || !statuses["confirmed"] || !statuses["resolved"] {
		t.Errorf("all statuses = %v, want dismissed+confirmed+resolved", statuses)
	}

	var d struct {
		Finding struct {
			Fingerprint string           `json:"fingerprint"`
			Status      string           `json:"status"`
			RuleID      string           `json:"rule_id"`
			Locations   []store.Location `json:"locations"`
			Verdict     *store.Verdict   `json:"verdict"`
		} `json:"finding"`
		History []struct {
			Kind  string `json:"kind"`
			Actor string `json:"actor"`
		} `json:"history"`
	}
	if code := getJSON(t, h, "/api/findings/"+fpC(), &d); code != http.StatusOK {
		t.Fatalf("remediated detail status %d", code)
	}
	if d.Finding.Fingerprint != fpC() || d.Finding.Status != "resolved" || d.Finding.RuleID != "go.err" {
		t.Errorf("remediated detail finding = %+v", d.Finding)
	}
	// The remediated detail carries the remediation verdict from the cache.
	if d.Finding.Verdict == nil || d.Finding.Verdict.Reason != "fixed upstream" ||
		d.Finding.Verdict.By != "agent" {
		t.Errorf("remediated detail verdict = %+v, want \"fixed upstream\" by agent", d.Finding.Verdict)
	}
	if len(d.Finding.Locations) != 1 || d.Finding.Locations[0] != (store.Location{Path: "b.go", Line: 1}) {
		t.Errorf("remediated detail locations = %v, want b.go:1", d.Finding.Locations)
	}
	kinds := map[string]bool{}
	for _, ev := range d.History {
		kinds[ev.Kind] = true
		if ev.Kind == "remediated" && ev.Actor != "agent" {
			t.Errorf("remediated event actor = %q, want agent", ev.Actor)
		}
	}
	if !kinds["detected"] || !kinds["remediated"] {
		t.Errorf("remediated history kinds = %v, want detected and remediated", kinds)
	}
}

func TestItems(t *testing.T) {
	h := New(fixture(t)).Handler()
	var d struct {
		Items []struct {
			Kind     string `json:"kind"`
			Question string `json:"question"`
		} `json:"items"`
	}
	getJSON(t, h, "/api/items", &d)
	if len(d.Items) != 1 || d.Items[0].Kind != "design" || d.Items[0].Question != "bind policy?" {
		t.Errorf("items = %+v", d.Items)
	}
}

func TestMetricsBuckets(t *testing.T) {
	h := New(fixture(t)).Handler()
	var m struct {
		Period string              `json:"period"`
		Count  int                 `json:"count"`
		Flow   map[string][]int    `json:"flow"`
		Triage []*float64          `json:"triage_median_hours"`
		Remed  []*float64          `json:"remediate_median_hours"`
		Actors map[string]int      `json:"actors"`
		Avg    map[string]*float64 `json:"resolve_avg_hours"`
	}
	if code := getJSON(t, h, "/api/metrics?period=weeks", &m); code != http.StatusOK {
		t.Fatalf("metrics status %d", code)
	}
	if m.Period != "weeks" || m.Count != 38 {
		t.Errorf("period %s count %d", m.Period, m.Count)
	}
	sum := func(xs []int) int {
		n := 0
		for _, x := range xs {
			n += x
		}
		return n
	}
	if sum(m.Flow["new"]) != 3 || sum(m.Flow["fixed"]) != 1 || sum(m.Flow["dismissed"]) != 1 {
		t.Errorf("flow totals = %v", m.Flow)
	}
	if len(m.Flow["new"]) != 38 || len(m.Triage) != 38 || len(m.Remed) != 38 {
		t.Errorf("series lengths = %d/%d/%d", len(m.Flow["new"]), len(m.Triage), len(m.Remed))
	}
	if m.Actors["agent"] != 1 || m.Actors["operator"] != 0 {
		t.Errorf("actors = %v", m.Actors)
	}
	if m.Avg["agent"] == nil || *m.Avg["agent"] != 24 {
		t.Errorf("avg resolve = %v", m.Avg)
	}
	// The only non-null triage median is 1h (the dismissal 1h after detection;
	// the confirmation sits at 2h in the next-to-last week bucket... both are
	// within the last week, so the bucket median of [1,2] is 1.5).
	saw := false
	for _, v := range m.Triage {
		if v != nil {
			saw = true
			if *v != 1.5 {
				t.Errorf("triage median = %v, want 1.5", *v)
			}
		}
	}
	if !saw {
		t.Error("no triage median recorded in any bucket")
	}

	// Bad period falls back to weeks, not an error.
	if code := getJSON(t, h, "/api/metrics?period=fortnights", &m); code != http.StatusOK || m.Period != "weeks" {
		t.Errorf("period fallback: %d %s", code, m.Period)
	}
}

func TestMetricsAbsentIs503(t *testing.T) {
	s := fixture(t)
	if err := os.Remove(filepath.Join(s.Cavet, "state", "metrics.json")); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	New(s).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// Card vs filter reconciliation (field-test finding): on a mixed fixture the
// overview's per-severity actionable counts must equal the findings endpoint's
// actionable-filtered per-severity row counts, by construction.
func TestOverviewMatchesActionableFilter(t *testing.T) {
	s := fixture(t)
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	more := []struct {
		fp, sev, status string
	}{
		{strings.Repeat("d4", 32), "critical", "open"},
		{strings.Repeat("e5", 32), "medium", "confirmed"},
		{strings.Repeat("f6", 32), "low", "deferred"},
		{strings.Repeat("07", 32), "info", "dismissed"},
		{strings.Repeat("18", 32), "info", "open"},
		{"", "info", "open"}, // empty severity folds to info
	}
	for i, m := range more {
		fp := m.fp
		if fp == "" {
			fp = strings.Repeat("28", 32)
			more[i].fp = fp
		}
		st.Findings = append(st.Findings, &store.Finding{Fingerprint: fp, Severity: m.sev,
			Status: m.status, DetectedAt: now, LastSeen: now})
	}
	if err := s.WriteState(st); err != nil {
		t.Fatal(err)
	}

	h := New(s).Handler()
	var o struct {
		Open map[string]int `json:"open"`
	}
	if code := getJSON(t, h, "/api/overview", &o); code != http.StatusOK {
		t.Fatalf("overview status %d", code)
	}
	var act struct {
		Total int `json:"total"`
	}
	getJSON(t, h, "/api/findings?status=actionable&per_page=100", &act)
	if act.Total != o.Open["total"] {
		t.Errorf("actionable total %d != overview total %d", act.Total, o.Open["total"])
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		var fr struct {
			Total int `json:"total"`
		}
		getJSON(t, h, "/api/findings?status=actionable&severity="+sev+"&per_page=100", &fr)
		if fr.Total != o.Open[sev] {
			t.Errorf("severity %s: actionable rows %d != overview card %d", sev, fr.Total, o.Open[sev])
		}
	}
	// Sum of the per-severity cards equals the total card.
	sum := 0
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		sum += o.Open[sev]
	}
	if sum != o.Open["total"] {
		t.Errorf("per-severity sum %d != total %d", sum, o.Open["total"])
	}
}

func TestServeStartRecompute(t *testing.T) {
	s := fixture(t)
	// Stale the cache (log append moved the cursor), then run the serve-start
	// path: it must recompute under the lock and clear staleness.
	ev, err := events.NewDeferred(time.Now().UTC(), events.ActorOperator, events.PhaseBuild,
		"eng", fpB(), "waiting on release")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ev); err != nil {
		t.Fatal(err)
	}
	if !s.MetricsStale() {
		t.Fatal("fixture must be stale after append")
	}
	if err := ensureMetrics(s); err != nil {
		t.Fatal(err)
	}
	if s.MetricsStale() {
		t.Fatal("serve start must clear staleness")
	}
	doc, err := s.LoadMetrics()
	if err != nil || doc == nil {
		t.Fatal(err)
	}
	for _, fr := range doc.Flow {
		if fr.Kind == "deferred" {
			return // the appended event is folded in
		}
	}
	t.Error("recomputed doc lacks the deferred flow record")
}

func TestIndexAndAssetServed(t *testing.T) {
	h := New(fixture(t)).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "security posture") {
		t.Errorf("index status %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/chart.umd.js", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Chart.js v4") {
		t.Errorf("chart asset status %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown path status %d", rec.Code)
	}
}
