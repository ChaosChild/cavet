package lookup

import (
	"context"
)

// OSV — primary advisory source (spec §5.3). No auth.

type OSV struct{ Base string }

func NewOSV() *OSV { return &OSV{Base: "https://api.osv.dev"} }

// OSVVuln carries the slices a triage decision needs: severity, affected
// ranges with fixed versions, aliases (CVE ids for KEV/EPSS enrichment).
type OSVVuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific map[string]string `json:"database_specific"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

func (o *OSV) GetVuln(ctx context.Context, id string) (*OSVVuln, error) {
	var v OSVVuln
	if err := getJSON(ctx, o.Base+"/v1/vulns/"+id, nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Severity returns the advisory's own severity label when it carries one.
func (v *OSVVuln) SeverityLabel() string {
	for _, a := range v.Affected {
		if s, ok := a.DatabaseSpecific["severity"]; ok && s != "" {
			return s
		}
	}
	return ""
}

// Fixed returns the first fixed version across ECOSYSTEM ranges. GIT ranges
// carry commit hashes, not versions — they are not fixed versions.
func (v *OSVVuln) Fixed() string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			if r.Type != "ECOSYSTEM" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// Thin reports whether this record is a cross-reference stub: OSV's bare-CVE
// entries carry a GIT range and aliases but no substance — the GHSA alias
// holds the detail (measured against CVE-2021-44228).
func (v *OSVVuln) Thin() bool {
	return v.Summary == "" && v.Fixed() == "" && len(v.Aliases) > 0
}

// Rich returns the richer record when this one is thin: follow one alias step.
func (v *OSVVuln) Rich(ctx context.Context, o *OSV) *OSVVuln {
	if !v.Thin() {
		return v
	}
	for _, a := range v.Aliases {
		if next, err := o.GetVuln(ctx, a); err == nil && !next.Thin() {
			return next // keep the queried id in the row; borrow the detail
		}
	}
	return v
}

// AffectedRange renders the first ECOSYSTEM range (GIT ranges carry commit
// hashes, not versions) as "introduced → fixed/last affected".
func (v *OSVVuln) AffectedRange() string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			if r.Type != "ECOSYSTEM" {
				continue
			}
			lo, hi := "", ""
			for _, e := range r.Events {
				if e.Introduced != "" && lo == "" {
					lo = e.Introduced
				}
				if e.LastAffected != "" {
					hi = e.LastAffected
				}
			}
			if lo == "" {
				lo = "0"
			}
			if hi == "" {
				hi = v.Fixed()
			}
			if hi != "" {
				return lo + " → " + hi
			}
			return lo + " →"
		}
	}
	return ""
}

// CVEAlias finds a CVE id among the aliases for KEV/EPSS enrichment.
func (v *OSVVuln) CVEAlias() string {
	for _, a := range v.Aliases {
		if len(a) > 4 && a[:4] == "CVE-" {
			return a
		}
	}
	if len(v.ID) > 4 && v.ID[:4] == "CVE-" {
		return v.ID
	}
	return ""
}

func (v *OSVVuln) URL() string { return "https://osv.dev/vulnerability/" + v.ID }

// QueryPurl returns advisory ids for a package coordinate (querybatch).
func (o *OSV) QueryPurl(ctx context.Context, purl string) ([]string, error) {
	var batch struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	body := map[string]any{
		"package": map[string]string{"purl": purl},
	}
	if err := postJSON(ctx, o.Base+"/v1/querybatch", body, &batch); err != nil {
		return nil, err
	}
	var ids []string
	for _, r := range batch.Results {
		for _, v := range r.Vulns {
			ids = append(ids, v.ID)
		}
	}
	return ids, nil // empty is a valid answer: this exact version is clean
}
