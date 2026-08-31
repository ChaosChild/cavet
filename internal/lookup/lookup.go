package lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Row is one identifier's answer, already reduced to what changes a triage
// decision (spec §5.3). Empty cells mean "not available" — degradation is
// visible, never silent, never fatal.
type Row struct {
	ID       string
	Severity string
	Range    string
	Fixed    string
	KEV      string
	EPSS     string
	Summary  string
	URL      string
	Stale    bool
	Notes    []string
}

var (
	reCVE  = regexp.MustCompile(`^(?i:CVE-\d{4}-\d{4,})$`)
	reGHSA = regexp.MustCompile(`^(?i:GHSA(?:-[a-z0-9]{4}){3})$`)
	reOSV  = regexp.MustCompile(`^[A-Z]+-\d{4}-\d{3,}$`) // GO-2021-xxx, PYSEC-…, RUSTSEC-…
	reCWE  = regexp.MustCompile(`^CWE-\d+$`)
	rePurl = regexp.MustCompile(`^pkg:[a-z0-9]+/.+@.+`)
)

// Kind classifies an identifier. Anything unmatched is a usage error naming
// the offending argument — that rejection is the no-leak guarantee (spec §5.3).
func Kind(id string) (string, error) {
	switch {
	case reCVE.MatchString(id):
		return "advisory", nil
	case reGHSA.MatchString(id), reOSV.MatchString(id):
		return "advisory", nil
	case rePurl.MatchString(id):
		return "package", nil
	case reCWE.MatchString(id):
		return "cwe", nil
	default:
		// Dotted/lowercase shapes may be scanner rule ids — resolved locally.
		// URLs and anything with whitespace never are; rejecting them is the
		// no-leak guarantee (spec §5.3).
		if strings.Contains(id, "://") || strings.ContainsAny(id, " \t") || len(id) > 200 {
			return "", fmt.Errorf("%q is not a CVE, GHSA/OSV, purl, CWE, or rule identifier", id)
		}
		if strings.Contains(id, ".") || strings.Contains(id, "-") {
			return "rule", nil
		}
	}
	return "", fmt.Errorf("%q is not a CVE, GHSA/OSV, purl, CWE, or rule identifier", id)
}

// Sources bundles the five adapters behind one constructor (each remains
// independently replaceable — no shared interface by design).
type Sources struct {
	OSV      *OSV
	KEV      *KEV
	EPSS     *EPSS
	NVD      *NVD
	Registry *Registry
	Cache    *Cache
	Rules    RuleCatalog
}

func NewSources(cache *Cache) *Sources {
	return &Sources{
		OSV: NewOSV(), KEV: NewKEV(cache), EPSS: NewEPSS(), NVD: NewNVD(),
		Registry: NewRegistry(), Cache: cache,
	}
}

// RuleCatalog resolves scanner rule ids locally from the engine-extracted
// catalogue (cache/advisories/rules-<digest8>.json, written by engine pull).
type RuleCatalog interface {
	Lookup(ruleID string) (summary, cwe, url string, ok bool)
}

// Run resolves identifiers to rows. Every source failure degrades a cell and
// records a note; nothing here fails the command (spec §5.3).
func Run(ctx context.Context, ids []string, src *Sources, refresh bool) ([]Row, error) {
	var rows []Row
	for _, id := range ids {
		kind, err := Kind(id)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "advisory":
			rows = append(rows, advisoryRow(ctx, id, src, refresh))
		case "package":
			rows = append(rows, packageRow(ctx, id, src, refresh))
		case "cwe":
			rows = append(rows, Row{ID: id, Severity: "—", Range: "—", Fixed: "—", KEV: "—",
				EPSS: "—", URL: "https://cwe.mitre.org/data/definitions/" +
					strings.TrimPrefix(id, "CWE-") + ".html"})
		case "rule":
			rows = append(rows, ruleRow(id, src))
		}
	}
	return rows, nil
}

func advisoryRow(ctx context.Context, id string, src *Sources, refresh bool) Row {
	row := Row{ID: id}
	// Canonical URL per id type so triage can cite identifier + URL (CVEs
	// resolve on NVD, GHSA/OSV ids on osv.dev).
	if reCVE.MatchString(id) {
		row.URL = "https://nvd.nist.gov/vuln/detail/" + id
	} else {
		row.URL = "https://osv.dev/vulnerability/" + id
	}

	// artefacts §11: fresh cache serves; expired refetches and falls back to
	// stale-with-marker offline; absent fetches and degrades on failure.
	var vuln *OSVVuln
	cached, _, fresh := src.Cache.Read("osv:" + id)
	if !refresh && fresh && len(cached) > 0 {
		vuln = new(OSVVuln)
		if json.Unmarshal(cached, vuln) != nil {
			vuln = nil
		}
	}
	notFound := false // identifier absent from the store — an answer, not a degradation
	if vuln == nil { // absent, stale, or --refresh: fetch with fallback to stale
		v, err := src.OSV.GetVuln(ctx, id)
		switch {
		case err == nil:
			vuln = v
		default:
			notFound = errors.Is(err, ErrNotFound)
			if len(cached) > 0 {
				vuln = new(OSVVuln)
				if json.Unmarshal(cached, vuln) != nil {
					vuln = nil
				} else {
					row.Stale = true
					row.Notes = append(row.Notes, "osv served stale (offline)")
				}
			}
		}
		if vuln != nil {
			vuln = vuln.Rich(ctx, src.OSV) // bare-CVE stubs: borrow the alias detail
			if b, err := json.Marshal(vuln); err == nil {
				_ = src.Cache.Write("osv:"+id, b)
			}
		}
	}
	if vuln == nil {
		if notFound {
			row.Notes = append(row.Notes, "osv no record")
			row.Severity, row.Range, row.Fixed = "no record", "no record", "no record"
		} else {
			row.Notes = append(row.Notes, "osv not available")
			row.Severity, row.Range, row.Fixed = "not available", "not available", "not available"
		}
		return row
	}
	row.Summary = vuln.Summary
	row.Severity = orNA(vuln.SeverityLabel())
	// Known advisory without a formal affected range is an answer of its own —
	// distinct from "not available" (spec §5.3 degradation stays visible).
	row.Range = orNoRange(vuln.AffectedRange())
	row.Fixed = orNA(vuln.Fixed())

	// Enrichment via the CVE alias — best effort, each cell independent.
	if cve := vuln.CVEAlias(); cve != "" {
		if src.KEV.IsKnown(ctx, cve) {
			row.KEV = "yes — known exploited"
		} else {
			row.KEV = "no"
		}
		if e, p, err := src.EPSS.Score(ctx, cve); err == nil {
			row.EPSS = fmt.Sprintf("%.1f%% (p%.0f)", e*100, p*100)
		} else {
			row.EPSS = "not available"
			row.Notes = append(row.Notes, "epss "+degraded(err))
		}
		if s, v, err := src.NVD.Vector(ctx, cve); err == nil {
			row.Notes = append(row.Notes, fmt.Sprintf("cvss %.1f %s", s, v))
		}
	} else {
		row.KEV, row.EPSS = "—", "—"
	}
	return row
}

func packageRow(ctx context.Context, id string, src *Sources, _ bool) Row {
	row := Row{ID: id}
	// OSV advisories for the coordinate, then registry existence.
	if ids, err := src.OSV.QueryPurl(ctx, id); err == nil {
		row.Range = fmt.Sprintf("%d advisories", len(ids))
		row.URL = "https://osv.dev/list?ecosystem=&q=" + id
		if len(ids) > 0 {
			row.Summary = "advisories: " + strings.Join(firstN(ids, 3), ", ")
		}
	} else {
		row.Range = "not available"
		row.Notes = append(row.Notes, "osv "+degraded(err))
	}
	if info, err := src.Registry.Lookup(ctx, id); err == nil {
		dep := "maintained"
		if info.Deprecated {
			dep = "deprecated"
		}
		row.Fixed = info.Version
		row.Severity = dep
		if row.URL == "" {
			row.URL = info.URL
		}
	} else {
		row.Fixed = "not available"
		row.Notes = append(row.Notes, "registry "+degraded(err))
	}
	row.KEV, row.EPSS = "—", "—"
	return row
}

func ruleRow(id string, src *Sources) Row {
	row := Row{ID: id, Severity: "—", Range: "—", KEV: "—", EPSS: "—"}
	if src.Rules == nil {
		row.Fixed, row.Summary = "—", "rule catalogue not extracted; run 'cavet engine pull'"
		return row
	}
	if summary, cwe, url, ok := src.Rules.Lookup(id); ok {
		row.Summary, row.Fixed, row.URL = summary, cwe, url
	} else {
		row.Summary = "rule not in catalogue"
	}
	return row
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func orNA(s string) string {
	if s == "" {
		return "not available"
	}
	return s
}

// orNoRange distinguishes "advisory known, no formal affected range recorded"
// from generic degradation.
func orNoRange(s string) string {
	if s == "" {
		return "no range recorded"
	}
	return s
}

func degraded(err error) string {
	if de, ok := err.(*ErrDegraded); ok {
		return "not available (" + de.Source + ": " + de.Err.Error() + ")"
	}
	return "not available (" + err.Error() + ")"
}
