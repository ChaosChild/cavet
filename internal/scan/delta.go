package scan

import (
	"time"

	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/projection"
	"github.com/ChaosChild/cavet/internal/store"
)

// Coverage describes what a scan actually looked at — remediation proof
// (spec §3.1: absence from a scan that did not cover the file, or did not run
// the scanner that found it, is not remediation).
type Coverage struct {
	Scanners []string
	AllPaths bool
	Paths    map[string]bool
}

func (c Coverage) scannerRan(s string) bool {
	for _, x := range c.Scanners {
		if x == s {
			return true
		}
	}
	return false
}

func (c Coverage) covers(path string) bool { return c.AllPaths || c.Paths[path] }

// FoldResult is the delta of one scan: events to append (in append order —
// detected/remediated first, surfaced last) and the replacement findings list.
type FoldResult struct {
	Events   []events.Event
	Findings []*store.Finding
}

// Fold merges scan results against state per cli-spec §8.3. New fingerprints
// get one detected event per location, so a rebuild reproduces state exactly;
// baseline fingerprints' detections predate the log's first scan and emit
// nothing. Surfaced events carry one entry per actionable finding shown —
// `cavet log --fingerprint` reconstructs presentation history (cli-spec
// §16.16).
func Fold(state *store.State, merged []*projection.MergedFinding, cov Coverage, o Options, now time.Time) (*FoldResult, error) {
	res := &FoldResult{}
	findings := make([]*store.Finding, len(state.Findings))
	copy(findings, state.Findings)
	byFP := make(map[string]*store.Finding, len(findings))
	for _, f := range findings {
		byFP[f.Fingerprint] = f
	}

	seen := map[string]bool{}
	for _, m := range merged {
		seen[m.Fingerprint] = true
		if f, ok := byFP[m.Fingerprint]; ok {
			f.LastSeen = now
			for _, loc := range m.Locations {
				if !hasLocation(f.Locations, loc) {
					f.Locations = append(f.Locations, store.Location{Path: loc.Path, Line: loc.Line})
					ev, err := events.NewDetected(now, o.Actor, o.Phase, o.Engine, m.Fingerprint, detData(m, loc))
					if err != nil {
						return nil, err
					}
					res.Events = append(res.Events, ev)
				}
			}
			continue
		}
		inBaseline := false
		for _, fp := range state.Baseline.Fingerprints {
			if fp == m.Fingerprint {
				inBaseline = true
				break
			}
		}
		f := &store.Finding{
			Fingerprint:        m.Fingerprint,
			RuleID:             m.RuleID,
			RuleKey:            m.RuleKey,
			OriginatingScanner: m.Scanner,
			AlsoDetectedBy:     m.CollapsedWith,
			Secret:             m.Secret,
			CollapsedWith:      m.CollapsedWith,
			Severity:           m.Severity,
			Description:        m.Description,
			DetectedAt:         now,
			LastSeen:           now,
			Status:             "open",
			InBaseline:         inBaseline,
		}
		for _, loc := range m.Locations {
			f.Locations = append(f.Locations, store.Location{Path: loc.Path, Line: loc.Line})
			if !inBaseline {
				ev, err := events.NewDetected(now, o.Actor, o.Phase, o.Engine, m.Fingerprint, detData(m, loc))
				if err != nil {
					return nil, err
				}
				res.Events = append(res.Events, ev)
			}
		}
		findings = append(findings, f)
		byFP[f.Fingerprint] = f
	}

	// Remediation pass: absence proves remediation only under coverage.
	kept := findings[:0]
	for _, f := range findings {
		if seen[f.Fingerprint] {
			kept = append(kept, f)
			continue
		}
		if cov.scannerRan(f.OriginatingScanner) && covered(cov, f.Locations) {
			ev, err := events.NewRemediated(now, o.Actor, o.Phase, o.Engine, f.Fingerprint,
				"absent from a scan that ran the originating scanner and covered every location")
			if err != nil {
				return nil, err
			}
			res.Events = append(res.Events, ev)
			continue // removed; the log is its archive (artefacts §6.2)
		}
		kept = append(kept, f)
	}
	res.Findings = kept

	// Surfaced: one event per actionable finding this scan presents.
	for _, m := range merged {
		f := byFP[m.Fingerprint]
		if f == nil || (f.Status != "open" && f.Status != "confirmed") {
			continue
		}
		ev, err := events.NewSurfaced(now, o.Actor, o.Phase, o.Engine, m.Fingerprint,
			events.SurfacedData{Context: o.Context})
		if err != nil {
			return nil, err
		}
		res.Events = append(res.Events, ev)
	}
	return res, nil
}

func covered(cov Coverage, locs []store.Location) bool {
	for _, l := range locs {
		if !cov.covers(l.Path) {
			return false
		}
	}
	return true
}

func hasLocation(locs []store.Location, loc projection.Location) bool {
	for _, l := range locs {
		if l.Path == loc.Path && l.Line == loc.Line {
			return true
		}
	}
	return false
}

func detData(m *projection.MergedFinding, loc projection.Location) events.DetectedData {
	return events.DetectedData{
		Rule:           m.RuleID,
		Severity:       events.Severity(m.Severity),
		Path:           loc.Path,
		Line:           loc.Line,
		Description:    m.Description,
		Scanner:        m.Scanner,
		AlsoDetectedBy: m.CollapsedWith,
	}
}
