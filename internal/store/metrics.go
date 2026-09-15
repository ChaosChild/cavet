package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
)

// MetricsCacheVersion is the schema version of state/metrics.json. A mismatch
// with the file on disk marks the cache stale (serve-task-1: full recompute is
// always correct, incremental is never attempted). Version 2 adds the
// Remediated records (serve-task-2: resolved rows come from the cache).
const MetricsCacheVersion = 2

// FlowRec is one verdict-flow event, bucketed serve-side by its timestamp.
// Kind is new|fixed|dismissed|deferred.
type FlowRec struct {
	TS   time.Time `json:"ts"`
	Kind string    `json:"kind"`
}

// ResolveRec is one remediation: when, by whom, and how long the finding had
// been open (hours from its first in-log detection – baseline findings' true
// detection predates the log, so this is a lower bound).
type ResolveRec struct {
	TS    time.Time `json:"ts"`
	Actor string    `json:"actor"`
	Hours float64   `json:"hours"`
}

// LagRec is one detection-to-triage latency in hours.
type LagRec struct {
	TS    time.Time `json:"ts"`
	Hours float64   `json:"hours"`
}

// RemediatedRec is one remediated finding the replay knew: enough of the row
// shape for the findings table's resolved filter and the detail panel (state
// holds current findings only, so the cache is their only serve-side home).
type RemediatedRec struct {
	Fingerprint  string    `json:"fingerprint"`
	Rule         string    `json:"rule"`
	Severity     string    `json:"severity"`
	Scanner      string    `json:"scanner"`
	DetectedAt   time.Time `json:"detected_at"`
	RemediatedAt time.Time `json:"remediated_at"`
}

// MetricsTrend holds actionable (open+confirmed) finding counts by severity
// at two points: the end of the replay, and the moment just after the scan
// before the last (surfaced/remediated batches mark scan ends in the log).
// The difference is the stat cards' "since last scan" trend.
type MetricsTrend struct {
	Current  map[string]int `json:"current"`
	Previous map[string]int `json:"previous,omitempty"`
}

// MetricsDoc is the precomputed aggregate state/metrics.json carries. The
// serve endpoints bucket these flat records per period without touching the
// log again.
type MetricsDoc struct {
	SchemaVersion int             `json:"schema_version"`
	Cursor        string          `json:"cursor"`
	ComputedAt    time.Time       `json:"computed_at"`
	Flow          []FlowRec       `json:"flow"`
	Resolve       []ResolveRec    `json:"resolve"`
	Triage        []LagRec        `json:"triage"`
	Remediated    []RemediatedRec `json:"remediated"`
	ScanTimes     []time.Time     `json:"scan_times"`
	Trend         MetricsTrend    `json:"trend"`
}

// ComputeMetrics replays the log into the metrics doc. It mirrors Rebuild's
// ordering (ts, line bytes) and identical-line collapse, but folds only what
// the aggregates need; item state stays in Rebuild's domain.
func ComputeMetrics(log []Enriched, cursor string) (*MetricsDoc, error) {
	sort.SliceStable(log, func(i, j int) bool {
		ti, tj := log[i].TS.UTC(), log[j].TS.UTC()
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return string(log[i].Raw) < string(log[j].Raw)
	})

	// Scan ends in the log: every scan writes its surfaced/remediated batch at
	// one timestamp (Fold, delta.go). Distinct timestamps of those kinds are
	// the scan boundaries; the second-to-last is the trend's baseline.
	var scanTimes []time.Time
	seenTS := map[int64]bool{}
	for _, en := range log {
		if (en.Kind == events.Surfaced || en.Kind == events.Remediated) && !seenTS[en.TS.UTC().UnixNano()] {
			seenTS[en.TS.UTC().UnixNano()] = true
			scanTimes = append(scanTimes, en.TS.UTC())
		}
	}
	var prevBoundary time.Time
	hasPrev := false
	if n := len(scanTimes); n >= 2 {
		prevBoundary, hasPrev = scanTimes[n-2], true
	}

	doc := &MetricsDoc{SchemaVersion: MetricsCacheVersion, Cursor: cursor,
		ComputedAt: time.Now().UTC(),
		Flow:       []FlowRec{}, Resolve: []ResolveRec{}, Triage: []LagRec{},
		Remediated: []RemediatedRec{},
		ScanTimes:  scanTimes, Trend: MetricsTrend{Current: map[string]int{}}}
	type liveRec struct {
		first      time.Time
		sev        string
		rule       string
		scanner    string
		actionable bool // open or confirmed – the posture view's counting rule
	}
	live := map[string]*liveRec{}
	openBySev := doc.Trend.Current
	hours := func(from, to time.Time) float64 {
		return to.Sub(from).Hours()
	}
	// setActionable keeps openBySev in step with status transitions that can
	// cross the actionable line in both directions (deferred -> confirmed).
	setActionable := func(lr *liveRec, val bool) {
		if val && !lr.actionable {
			openBySev[lr.sev]++
			openBySev["total"]++
		} else if !val && lr.actionable {
			openBySev[lr.sev]--
			openBySev["total"]--
		}
		lr.actionable = val
	}

	snapshotted := false
	snapshot := func() {
		if snapshotted || !hasPrev {
			return
		}
		m := make(map[string]int, len(openBySev))
		for k, v := range openBySev {
			m[k] = v
		}
		doc.Trend.Previous = m
		snapshotted = true
	}

	dup := map[string]bool{}
	for _, en := range log {
		if dup[string(en.Raw)] {
			continue
		}
		dup[string(en.Raw)] = true

		// Snapshot once every event at or before the trend boundary is folded.
		if hasPrev && en.TS.UTC().After(prevBoundary) {
			snapshot()
		}

		switch en.Kind {
		case events.Detected:
			if _, ok := live[en.Fingerprint]; ok {
				continue // re-detection of a live finding: a location add, not a new one
			}
			d, ok := en.Payload().(events.DetectedData)
			if !ok {
				return nil, &ParseError{File: en.File, Err: fmt.Errorf("detected payload mismatch")}
			}
			live[en.Fingerprint] = &liveRec{first: en.TS.UTC(), sev: string(d.Severity),
				rule: d.Rule, scanner: d.Scanner, actionable: true}
			openBySev[string(d.Severity)]++
			openBySev["total"]++
			doc.Flow = append(doc.Flow, FlowRec{TS: en.TS.UTC(), Kind: "new"})

		case events.Triaged:
			lr, ok := live[en.Fingerprint]
			if !ok {
				// Stale verdict for a finding the replay no longer knows
				// (e.g. remediated and re-baselined earlier). It cannot
				// affect any aggregate, so skip it; the log is the source
				// of truth and malformed input still errors below.
				continue
			}
			d, ok := en.Payload().(events.TriagedData)
			if !ok {
				return nil, &ParseError{File: en.File, Err: fmt.Errorf("triaged payload mismatch")}
			}
			doc.Triage = append(doc.Triage, LagRec{TS: en.TS.UTC(), Hours: hours(lr.first, en.TS.UTC())})
			if d.Verdict == events.VerdictDismissed {
				setActionable(lr, false)
				doc.Flow = append(doc.Flow, FlowRec{TS: en.TS.UTC(), Kind: "dismissed"})
			} else {
				setActionable(lr, true)
			}

		case events.Suppressed:
			lr, ok := live[en.Fingerprint]
			if !ok {
				continue // stale verdict: cannot affect any aggregate
			}
			setActionable(lr, false)
			delete(live, en.Fingerprint)

		case events.Deferred:
			lr, ok := live[en.Fingerprint]
			if !ok {
				continue // stale verdict: cannot affect any aggregate
			}
			setActionable(lr, false)
			doc.Flow = append(doc.Flow, FlowRec{TS: en.TS.UTC(), Kind: "deferred"})

		case events.Remediated:
			lr, ok := live[en.Fingerprint]
			if !ok {
				continue // stale remediation: no live finding, no flow record
			}
			setActionable(lr, false)
			delete(live, en.Fingerprint)
			doc.Flow = append(doc.Flow, FlowRec{TS: en.TS.UTC(), Kind: "fixed"})
			doc.Resolve = append(doc.Resolve, ResolveRec{TS: en.TS.UTC(),
				Actor: string(en.Actor), Hours: hours(lr.first, en.TS.UTC())})
			doc.Remediated = append(doc.Remediated, RemediatedRec{Fingerprint: en.Fingerprint,
				Rule: lr.rule, Severity: lr.sev, Scanner: lr.scanner,
				DetectedAt: lr.first, RemediatedAt: en.TS.UTC()})

		case events.Raised, events.Resolved, events.Rebaselined, events.Surfaced:
			// nothing aggregate-relevant; surfaced already marked a scan end
		default:
			// unknown kinds preserved in the log, excluded from the fold (§10)
		}
	}
	snapshot()
	return doc, nil
}

// RefreshMetrics recomputes and writes state/metrics.json. Callers already
// holding the artefact lock (scan end, rebuild) may call it directly; serve
// start acquires the lock first.
func (s *Store) RefreshMetrics() error {
	log, err := s.ReadLog()
	if err != nil {
		return err
	}
	cursor, err := s.LogCursor()
	if err != nil {
		return err
	}
	doc, err := ComputeMetrics(log, cursor)
	if err != nil {
		return err
	}
	return s.WriteMetrics(doc)
}

// WriteMetrics persists the doc atomically.
func (s *Store) WriteMetrics(doc *MetricsDoc) error {
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(filepath.Join(s.Cavet, "state", "metrics.json"), append(out, '\n'))
}

// LoadMetrics returns the cached doc, or nil when absent. Corrupt files are
// reported as errors; a corrupt cache is stale by definition.
func (s *Store) LoadMetrics() (*MetricsDoc, error) {
	b, err := os.ReadFile(filepath.Join(s.Cavet, "state", "metrics.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc MetricsDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("state/metrics.json: %w", err)
	}
	return &doc, nil
}

// MetricsStale reports whether the cache must be recomputed: missing,
// unreadable, schema-version mismatch, or cursor mismatch against the log
// directory (file names and sizes; appends only grow files, monthly rollover
// adds one).
func (s *Store) MetricsStale() bool {
	doc, err := s.LoadMetrics()
	if err != nil || doc == nil {
		return true
	}
	if doc.SchemaVersion != MetricsCacheVersion {
		return true
	}
	cursor, err := s.LogCursor()
	if err != nil || cursor != doc.Cursor {
		return true
	}
	return false
}

// LogCursor fingerprints the log directory cheaply, without parsing.
func (s *Store) LogCursor() (string, error) {
	files, err := s.logGlob()
	if err != nil {
		return "", err
	}
	cursor := ""
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			return "", err
		}
		cursor += fmt.Sprintf("%s:%d;", filepath.Base(f), fi.Size())
	}
	return cursor, nil
}
