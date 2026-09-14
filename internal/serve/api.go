package serve

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ChaosChild/cavet/internal/scan"
	"github.com/ChaosChild/cavet/internal/store"
)

// retryOnce re-runs a read a single time after a pause: state files are
// written atomically, but a read racing a rename on some platforms can see a
// truncated body, and one retry collapses that window (serve-task-1 D7).
func retryOnce(f func() error) error {
	err := f()
	if err == nil {
		return nil
	}
	time.Sleep(25 * time.Millisecond)
	return f()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheck // best-effort body write
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// shortEngine renders name@sha256:4f2a… for the header line (cli-spec §4.1).
func shortEngine(ref string) string {
	i := strings.Index(ref, "@sha256:")
	if i < 0 {
		return ref
	}
	d := ref[i+8:]
	if len(d) > 4 {
		d = d[:4] + "…"
	}
	return ref[:i] + "@sha256:" + d
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func actionable(f *store.Finding) bool { return f.Status == "open" || f.Status == "confirmed" }

// --- /api/overview ---

type lastScanView struct {
	Scope    string   `json:"scope"`
	Phase    string   `json:"phase"`
	Engine   string   `json:"engine"`
	At       string   `json:"at"`
	Scanners []string `json:"scanners"`
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	var st *store.State
	if err := retryOnce(func() error { var e error; st, e = s.st.LoadState(); return e }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var ls *scan.LastScan
	if err := retryOnce(func() error { var e error; ls, e = scan.ReadLastScan(s.st); return e }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var doc *store.MetricsDoc
	if err := retryOnce(func() error { var e error; doc, e = s.st.LoadMetrics(); return e }); err != nil {
		doc = nil // an unreadable cache degrades trends, not the posture cards
	}

	resp := struct {
		AsOf       string                `json:"as_of"`
		Repo       string                `json:"repo"`
		Engine     string                `json:"engine,omitempty"`
		Open       map[string]int        `json:"open"`
		Trend      map[string]int        `json:"trend,omitempty"`
		TrendKnown bool                  `json:"trend_known"`
		Oldest     map[string]*time.Time `json:"oldest,omitempty"`
		Baseline   int                   `json:"baseline"`
		LastScan   *lastScanView         `json:"last_scan,omitempty"`
		OpenItems  int                   `json:"open_items"`
		Scanners   []string              `json:"scanners,omitempty"`
	}{
		Repo:   filepath.Base(s.st.Root),
		Open:   map[string]int{"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
		Oldest: map[string]*time.Time{},
	}
	severities := []string{"critical", "high", "medium", "low"}
	for _, f := range st.Findings {
		if !actionable(f) {
			continue
		}
		resp.Open["total"]++
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		if _, known := sevRank[sev]; !known {
			continue // unexpected severity: total only, never a stray JSON key
		}
		resp.Open[sev]++
		if sev == "info" {
			continue
		}
		cur, ok := resp.Oldest[sev]
		if !ok || f.DetectedAt.Before(*cur) {
			t := f.DetectedAt
			resp.Oldest[f.Severity] = &t
		}
	}
	for _, sev := range severities {
		if _, ok := resp.Oldest[sev]; !ok {
			resp.Oldest[sev] = nil
		}
	}
	resp.Baseline = len(st.Baseline.Fingerprints)
	resp.OpenItems = len(st.Items)

	if ls != nil {
		resp.LastScan = &lastScanView{Scope: ls.Scope, Phase: ls.Phase, Engine: shortEngine(ls.Engine),
			At: ls.At, Scanners: ls.Scanners}
		resp.Scanners = ls.Scanners
		resp.Engine = shortEngine(ls.Engine)
		resp.AsOf = ls.At
	} else {
		resp.AsOf = st.RebuiltAt.UTC().Format(time.RFC3339)
	}

	// Trend: replay-current minus the snapshot after the scan before the
	// last. The headline counts above stay state-authoritative.
	if doc != nil && doc.Trend.Previous != nil {
		resp.TrendKnown = true
		resp.Trend = map[string]int{}
		for _, sev := range []string{"total", "critical", "high", "medium", "low", "info"} {
			resp.Trend[sev] = doc.Trend.Current[sev] - doc.Trend.Previous[sev]
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- /api/findings ---

type findingRow struct {
	ID         string           `json:"id"`
	Severity   string           `json:"severity"`
	Rule       string           `json:"rule"`
	Scanner    string           `json:"scanner"`
	Locations  []store.Location `json:"locations"`
	Status     string           `json:"status"`
	Verdict    string           `json:"verdict,omitempty"`
	VerdictBy  string           `json:"verdict_by,omitempty"`
	VerdictAt  *time.Time       `json:"verdict_at,omitempty"`
	DetectedAt time.Time        `json:"detected_at"`
	LastSeen   time.Time        `json:"last_seen"`
}

func rowOf(f *store.Finding) findingRow {
	row := findingRow{ID: f.DisplayID, Severity: f.Severity, Rule: f.RuleID,
		Scanner: f.OriginatingScanner, Locations: f.Locations, Status: f.Status,
		DetectedAt: f.DetectedAt, LastSeen: f.LastSeen}
	if f.Verdict != nil {
		row.Verdict = f.Verdict.Reason
		row.VerdictBy = f.Verdict.By
		t := f.Verdict.At
		row.VerdictAt = &t
	}
	return row
}

func matchesScanner(f *store.Finding, sc string) bool {
	if f.OriginatingScanner == sc {
		return true
	}
	for _, a := range f.AlsoDetectedBy {
		if a == sc {
			return true
		}
	}
	return false
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scanner := q.Get("scanner")
	severity := q.Get("severity")
	status := q.Get("status")
	page, err := strconv.Atoi(q.Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	perPage, err := strconv.Atoi(q.Get("per_page"))
	if err != nil || perPage < 1 {
		perPage = 6 // the mock's default
	}
	if perPage > 100 {
		perPage = 100
	}

	var st *store.State
	if err := retryOnce(func() error { var e error; st, e = s.st.LoadState(); return e }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var filtered []*store.Finding
	for _, f := range st.Findings {
		if scanner != "" && !matchesScanner(f, scanner) {
			continue
		}
		if severity != "" && f.Severity != severity {
			continue
		}
		if status != "" && f.Status != status {
			continue
		}
		filtered = append(filtered, f)
	}
	sort.Slice(filtered, func(i, j int) bool {
		ri, rj := sevRank[filtered[i].Severity], sevRank[filtered[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return filtered[i].DetectedAt.Before(filtered[j].DetectedAt)
	})

	total := len(filtered)
	pages := (total + perPage - 1) / perPage
	if pages < 1 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	lo := (page - 1) * perPage
	hi := lo + perPage
	if hi > total {
		hi = total
	}
	rows := []findingRow{}
	for _, f := range filtered[lo:hi] {
		rows = append(rows, rowOf(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rows": rows, "total": total, "page": page, "pages": pages, "per_page": perPage,
	})
}

// --- /api/findings/{display-id} ---

type histEvent struct {
	TS     time.Time       `json:"ts"`
	Kind   string          `json:"kind"`
	Actor  string          `json:"actor"`
	Phase  string          `json:"phase"`
	Detail json.RawMessage `json:"detail,omitempty"`
}

func (s *Server) handleFindingDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	if id == "" {
		writeErr(w, http.StatusNotFound, "finding id required")
		return
	}
	var st *store.State
	if err := retryOnce(func() error { var e error; st, e = s.st.LoadState(); return e }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var f *store.Finding
	for _, x := range st.Findings {
		if x.DisplayID == id || x.Fingerprint == id {
			f = x
			break
		}
	}
	if f == nil {
		writeErr(w, http.StatusNotFound, "unknown finding "+id)
		return
	}
	log, err := s.st.ReadLog()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var history []histEvent
	for _, en := range log {
		if en.Fingerprint != f.Fingerprint {
			continue
		}
		he := histEvent{TS: en.TS, Kind: string(en.Kind), Actor: string(en.Actor), Phase: string(en.Phase)}
		if p := en.Payload(); p != nil {
			if b, merr := json.Marshal(p); merr == nil {
				he.Detail = b
			}
		}
		history = append(history, he)
	}
	sort.SliceStable(history, func(i, j int) bool { return history[i].TS.Before(history[j].TS) })
	if history == nil {
		history = []histEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"finding": f, "history": history})
}

// --- /api/items ---

func (s *Server) handleItems(w http.ResponseWriter, _ *http.Request) {
	var st *store.State
	if err := retryOnce(func() error { var e error; st, e = s.st.LoadState(); return e }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	items := st.Items
	if items == nil {
		items = []store.Item{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// --- /api/metrics ---

// bucketCounts mirror the mock's period switcher: 30 days, 38 weeks (year to
// date), 24 months.
var bucketCounts = map[string]int{"days": 30, "weeks": 38, "months": 24}

func periodStart(t time.Time, period string) time.Time {
	t = t.UTC()
	switch period {
	case "days":
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	case "weeks":
		off := (int(t.Weekday()) + 6) % 7 // back to Monday
		return time.Date(t.Year(), t.Month(), t.Day()-off, 0, 0, 0, 0, time.UTC)
	default:
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
}

func bucketStarts(now time.Time, period string, n int) []time.Time {
	anchor := periodStart(now, period)
	starts := make([]time.Time, n)
	for i := 0; i < n; i++ {
		switch period {
		case "days":
			starts[n-1-i] = anchor.AddDate(0, 0, -i)
		case "weeks":
			starts[n-1-i] = anchor.AddDate(0, 0, -7*i)
		default:
			starts[n-1-i] = anchor.AddDate(0, -i, 0)
		}
	}
	return starts
}

func bucketOf(ts time.Time, starts []time.Time) int {
	for i := len(starts) - 1; i >= 0; i-- {
		if !ts.UTC().Before(starts[i]) {
			return i
		}
	}
	return 0 // older than the window folds into the first bucket
}

func median(xs []float64) *float64 {
	if len(xs) == 0 {
		return nil
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	m := len(s) / 2
	var v float64
	if len(s)%2 == 1 {
		v = s[m]
	} else {
		v = (s[m-1] + s[m]) / 2
	}
	return &v
}

func mean(xs []float64) *float64 {
	if len(xs) == 0 {
		return nil
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	v := sum / float64(len(xs))
	return &v
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if _, ok := bucketCounts[period]; !ok {
		period = "weeks"
	}
	var doc *store.MetricsDoc
	if err := retryOnce(func() error { var e error; doc, e = s.st.LoadMetrics(); return e }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if doc == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"metrics cache absent; it regenerates at the next scan, rebuild, or serve start")
		return
	}

	n := bucketCounts[period]
	starts := bucketStarts(time.Now(), period, n)
	flow := map[string][]int{"new": make([]int, n), "fixed": make([]int, n),
		"dismissed": make([]int, n), "deferred": make([]int, n)}
	for _, fr := range doc.Flow {
		if series, ok := flow[fr.Kind]; ok {
			series[bucketOf(fr.TS, starts)]++
		}
	}
	triageLag := make([][]float64, n)
	remedLag := make([][]float64, n)
	for _, l := range doc.Triage {
		triageLag[bucketOf(l.TS, starts)] = append(triageLag[bucketOf(l.TS, starts)], l.Hours)
	}
	for _, rr := range doc.Resolve {
		remedLag[bucketOf(rr.TS, starts)] = append(remedLag[bucketOf(rr.TS, starts)], rr.Hours)
	}
	triageMed := make([]*float64, n)
	remedMed := make([]*float64, n)
	for i := 0; i < n; i++ {
		triageMed[i] = median(triageLag[i])
		remedMed[i] = median(remedLag[i])
	}
	actors := map[string]int{}
	actorHours := map[string][]float64{}
	for _, rr := range doc.Resolve {
		actors[rr.Actor]++
		actorHours[rr.Actor] = append(actorHours[rr.Actor], rr.Hours)
	}
	avg := map[string]*float64{}
	for a, xs := range actorHours {
		avg[a] = mean(xs)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"period": period, "count": n, "as_of": doc.ComputedAt,
		"flow":                   flow,
		"triage_median_hours":    triageMed,
		"remediate_median_hours": remedMed,
		"actors":                 actors,
		"resolve_avg_hours":      avg,
	})
}
