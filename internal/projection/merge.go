package projection

import (
	"strings"

	"github.com/ChaosChild/cavet/internal/fingerprint"
)

// MergedFinding is the post-collapse, fingerprinted unit the delta fold
// consumes (cli-spec §8).
type MergedFinding struct {
	Fingerprint    string
	RuleID         string
	RuleKey        string
	CWE            string
	Severity       string
	Description    string
	Scanner        string // originating scanner
	AlsoDetectedBy []string
	CollapsedWith  []string // rule ids folded in via secret dedup
	Secret         bool
	Locations      []Location
}

type Location struct {
	Path string
	Line int
}

// Merge collapses cross-scanner secret duplicates before fingerprinting, then
// groups everything else by finding fingerprint (SPECIFICATION.md §3.3,
// cli-spec §8.1–8.2).
func Merge(fs []Finding) []*MergedFinding {
	type secretGroup struct {
		winner Finding
		losers []Finding
	}
	groups := map[string]*secretGroup{}
	var groupOrder []string
	var rest []Finding

	for _, f := range fs {
		if isSecretFinding(f) && strings.TrimSpace(f.Snippet) != "" {
			key := fingerprint.Secret(normSpan(f.Snippet), f.Path)
			g, ok := groups[key]
			if !ok {
				groups[key] = &secretGroup{winner: f}
				groupOrder = append(groupOrder, key)
				continue
			}
			if scannerPriority(f.Scanner) < scannerPriority(g.winner.Scanner) {
				g.losers = append(g.losers, g.winner)
				g.winner = f
			} else {
				g.losers = append(g.losers, f)
			}
		} else {
			rest = append(rest, f)
		}
	}

	var out []*MergedFinding
	for _, key := range groupOrder {
		g := groups[key]
		m := toMerged(g.winner, true)
		for _, l := range g.losers {
			m.AlsoDetectedBy = append(m.AlsoDetectedBy, l.Scanner)
			m.CollapsedWith = append(m.CollapsedWith, l.RuleID)
			m.Locations = appendUniqueLoc(m.Locations, Location{Path: l.Path, Line: l.Line})
		}
		out = append(out, m)
	}

	byFP := map[string]*MergedFinding{}
	for _, f := range rest {
		fp := fingerprint.Of(fingerprint.RuleKey(f.CWE, f.RuleID), normSpan(f.Snippet))
		if m, ok := byFP[fp]; ok {
			m.Locations = appendUniqueLoc(m.Locations, Location{Path: f.Path, Line: f.Line})
			continue
		}
		m := toMerged(f, false)
		m.Fingerprint = fp
		byFP[fp] = m
		out = append(out, m)
	}
	return out
}

func toMerged(f Finding, secret bool) *MergedFinding {
	rk := fingerprint.RuleKey(f.CWE, f.RuleID)
	return &MergedFinding{
		Fingerprint: fingerprint.Of(rk, normSpan(f.Snippet)),
		RuleID:      f.RuleID,
		RuleKey:     rk,
		CWE:         f.CWE,
		Severity:    f.Severity,
		Description: f.Desc,
		Scanner:     f.Scanner,
		Secret:      secret,
		Locations:   []Location{{Path: f.Path, Line: f.Line}},
	}
}

// scannerPriority orders secret-collapse winners: gitleaks is the dedicated
// secret scanner, so it keeps the rule id (spec §3.3: first scanner wins).
func scannerPriority(s string) int {
	if s == "gitleaks" {
		return 0
	}
	return 1
}

// isSecretFinding identifies the secret category: all gitleaks findings; Trivy
// only via its secret-scanner rules — provider patterns whose ids name the
// secret kind (spike §6). Vuln ids (CVE-*) and misconfig ids (AWS-*/AVD-*)
// never contain these substrings.
func isSecretFinding(f Finding) bool {
	if f.Scanner == "gitleaks" {
		return true
	}
	if f.Scanner == "trivy" {
		return strings.Contains(f.RuleID, "secret") || strings.Contains(f.RuleID, "token")
	}
	return false
}

// normSpan normalises the matched span for hashing; masking is consistent
// across scanners, so identical spans collapse regardless of emitter.
func normSpan(s string) string {
	n, err := fingerprint.Normalise([]byte(s), 1)
	if err != nil {
		return strings.Join(strings.Fields(s), " ")
	}
	return n
}

func appendUniqueLoc(locs []Location, loc Location) []Location {
	for _, l := range locs {
		if l == loc {
			return locs
		}
	}
	return append(locs, loc)
}
