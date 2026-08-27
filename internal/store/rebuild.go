package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ChaosChild/cavet/internal/events"
)

// Rebuild replays the log into state/ (artefacts §6). Ordering is imposed by
// (ts, line bytes), so the result is deterministic regardless of physical line
// order — required after merge=union merges (§6.1). Baseline membership is not
// log-derivable; an existing baseline.json is preserved (§6.3).
func (s *Store) Rebuild() (*State, error) {
	log, err := s.ReadLog()
	if err != nil {
		return nil, err
	}
	sort.SliceStable(log, func(i, j int) bool {
		ti, tj := log[i].TS.UTC(), log[j].TS.UTC()
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return bytes.Compare(log[i].Raw, log[j].Raw) < 0
	})

	st := &State{RebuiltAt: time.Now().UTC(),
		Findings:     []*Finding{},
		Items:        []Item{},
		findingsByFP: map[string]*Finding{},
		itemsByID:    map[string]bool{}}
	seen := map[string]bool{}
	unknownKinds := 0

	for _, en := range log {
		// Identical lines collapse silently — expected after branch merges
		// (artefacts §6.2). One guard covers every kind.
		if seen[string(en.Raw)] {
			continue
		}
		seen[string(en.Raw)] = true

		switch en.Kind {
		case events.Detected:
			d, ok := en.Payload().(events.DetectedData)
			if !ok {
				return nil, &ParseError{File: en.File, Err: fmt.Errorf("detected payload mismatch")}
			}
			if prev, exists := st.findingsByFP[en.Fingerprint]; exists {
				appendUniqueLoc(&prev.Locations, Location{Path: d.Path, Line: d.Line})
				prev.LastSeen = en.TS
				continue
			}
			f := &Finding{
				Fingerprint:        en.Fingerprint,
				RuleKey:            d.Rule, // the log carries no CWE; scan-time keys live in the fingerprint
				RuleID:             d.Rule,
				OriginatingScanner: d.Scanner,
				AlsoDetectedBy:     d.AlsoDetectedBy,
				Secret:             d.Scanner == "gitleaks" || len(d.AlsoDetectedBy) > 0 || isTrivySecretRule(d.Rule),
				Severity:           string(d.Severity),
				Description:        d.Description,
				Locations:          []Location{{Path: d.Path, Line: d.Line}},
				DetectedAt:         en.TS,
				LastSeen:           en.TS,
				Status:             "open",
			}
			st.Findings = append(st.Findings, f)
			st.findingsByFP[f.Fingerprint] = f

		case events.Triaged:
			f, ok := st.findingsByFP[en.Fingerprint]
			if !ok {
				return nil, &ParseError{File: en.File,
					Err: fmt.Errorf("triaged references unknown fingerprint %s", short(en.Fingerprint))}
			}
			d, ok := en.Payload().(events.TriagedData)
			if !ok {
				return nil, &ParseError{File: en.File, Err: fmt.Errorf("triaged payload mismatch")}
			}
			f.Verdict = &Verdict{Verdict: string(d.Verdict), Confidence: string(d.Confidence),
				Reason: d.Reason, Sources: d.Sources, At: en.TS, By: string(en.Actor)}
			if d.Verdict == events.VerdictDismissed {
				f.Status = "dismissed"
			} else {
				f.Status = "confirmed"
			}

		case events.Suppressed:
			if err := setStatus(st, en, "suppressed"); err != nil {
				return nil, err
			}
		case events.Deferred:
			if err := setStatus(st, en, "deferred"); err != nil {
				return nil, err
			}

		case events.Remediated:
			f, ok := st.findingsByFP[en.Fingerprint]
			if !ok {
				return nil, &ParseError{File: en.File,
					Err: fmt.Errorf("remediated references unknown fingerprint %s", short(en.Fingerprint))}
			}
			removeFinding(st, f)

		case events.Raised:
			d, ok := en.Payload().(events.RaisedData)
			if !ok {
				return nil, &ParseError{File: en.File, Err: fmt.Errorf("raised payload mismatch")}
			}
			id := ItemID(en.Event)
			if _, dup := st.itemsByID[id]; dup {
				id += "-2" // hash collision guard; identical content already collapsed above
			}
			item := Item{ID: id, Kind: string(d.Kind), Question: d.Question,
				Fingerprint: d.Fingerprint, RaisedAt: en.TS, RaisedBy: string(en.Actor)}
			st.Items = append(st.Items, item)
			st.itemsByID[id] = true

		case events.Resolved:
			d, ok := en.Payload().(events.ResolvedData)
			if !ok {
				return nil, &ParseError{File: en.File, Err: fmt.Errorf("resolved payload mismatch")}
			}
			if _, ok := st.itemsByID[d.Item]; !ok {
				return nil, &ParseError{File: en.File,
					Err: fmt.Errorf("resolved references unknown item %q", d.Item)}
			}
			removeItem(st, d.Item)

		case events.Rebaselined, events.Surfaced:
			// rebaselined: membership arrives via baseline.json (§6.3).
			// surfaced: presentation is history, not state (§6.2).
		default:
			unknownKinds++ // preserved verbatim in the log, excluded from the fold (§10)
		}
	}
	if unknownKinds > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d unknown-kind events preserved, excluded from fold\n", unknownKinds)
	}

	if err := s.loadBaseline(st); err != nil {
		return nil, err
	}
	assignDisplayIDs(st.Findings)
	return st, s.writeState(st)
}

// ItemID derives the content-based open-item id for a raised event: replay
// order is not authoritative after merge=union merges (artefacts §6.2), so
// identity comes from the event's canonical bytes. Shared by `cavet raise`
// and rebuild — they can never disagree.
func ItemID(ev events.Event) string {
	sum := sha256.Sum256(events.Canonical(ev))
	return "it-" + hex.EncodeToString(sum[:])[:8]
}

// WriteBaseline persists baseline.json (init and rebaseline only — artefacts
// §9.3).
func (s *Store) WriteBaseline(b Baseline) error {
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(filepath.Join(s.Cavet, "state", "baseline.json"), append(out, '\n'))
}

func setStatus(st *State, en Enriched, status string) error {
	f, ok := st.findingsByFP[en.Fingerprint]
	if !ok {
		return &ParseError{File: en.File,
			Err: fmt.Errorf("%s references unknown fingerprint %s", en.Kind, short(en.Fingerprint))}
	}
	f.Status = status
	return nil
}

func removeFinding(st *State, f *Finding) {
	delete(st.findingsByFP, f.Fingerprint)
	out := st.Findings[:0]
	for _, x := range st.Findings {
		if x != f {
			out = append(out, x)
		}
	}
	st.Findings = out
}

func removeItem(st *State, id string) {
	delete(st.itemsByID, id)
	out := st.Items[:0]
	for _, x := range st.Items {
		if x.ID != id {
			out = append(out, x)
		}
	}
	st.Items = out
}

func appendUniqueLoc(locs *[]Location, loc Location) {
	for _, l := range *locs {
		if l == loc {
			return
		}
	}
	*locs = append(*locs, loc)
}

// WriteState persists findings.json and items.json atomically. Scan uses this
// to rewrite state wholesale with fresh observations — last_seen included —
// where a rebuild would decay it (artefacts §6.4). Baseline is never touched.
func (s *Store) WriteState(st *State) error { return s.writeState(st) }

// AssignDisplayIDs gives each finding the shortest fingerprint prefix that is
// unique among live findings (artefacts §5). Exported for the scan pipeline,
// which inserts findings between full rebuilds.
func AssignDisplayIDs(fs []*Finding) { assignDisplayIDs(fs) }

// assignDisplayIDs gives each finding the shortest fingerprint prefix that is
// unique among live findings, starting at 6 hex and extending on collision
// (artefacts §5).
func assignDisplayIDs(fs []*Finding) {
	remaining := fs
	for length := 6; len(remaining) > 0 && length <= 64; length++ {
		counts := map[string]int{}
		for _, f := range remaining {
			counts[f.Fingerprint[:length]]++
		}
		next := remaining[:0]
		for _, f := range remaining {
			p := f.Fingerprint[:length]
			if counts[p] == 1 {
				f.DisplayID = p
			} else {
				next = append(next, f)
			}
		}
		remaining = next
	}
	for _, f := range remaining { // identical fingerprints cannot both be live
		f.DisplayID = f.Fingerprint
	}
}

// loadBaseline preserves an existing baseline.json; rebuild never fabricates
// debt accounting (artefacts §6.3).
func (s *Store) loadBaseline(st *State) error {
	p := filepath.Join(s.Cavet, "state", "baseline.json")
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &st.Baseline); err != nil {
		return fmt.Errorf("state/baseline.json: %w (derived file; re-run 'cavet rebaseline' to regenerate)", err)
	}
	return nil
}

func (s *Store) writeState(st *State) error {
	findings, err := json.MarshalIndent(struct {
		RebuiltAt time.Time  `json:"rebuilt_at"`
		Findings  []*Finding `json:"findings"`
	}{st.RebuiltAt, st.Findings}, "", "  ")
	if err != nil {
		return err
	}
	items, err := json.MarshalIndent(struct {
		RebuiltAt time.Time `json:"rebuilt_at"`
		Items     []Item    `json:"items"`
	}{st.RebuiltAt, st.Items}, "", "  ")
	if err != nil {
		return err
	}
	if err := AtomicWrite(filepath.Join(s.Cavet, "state", "findings.json"), append(findings, '\n')); err != nil {
		return err
	}
	return AtomicWrite(filepath.Join(s.Cavet, "state", "items.json"), append(items, '\n'))
}

func short(fp string) string {
	if len(fp) > 6 {
		return fp[:6]
	}
	return fp
}

// isTrivySecretRule approximates Trivy's secret-scanner rule ids
// (e.g. slack-access-token). The scan path knows precisely; replay can only
// approximate from the rule id.
func isTrivySecretRule(rule string) bool {
	return strings.Contains(rule, "secret") || strings.Contains(rule, "token")
}
