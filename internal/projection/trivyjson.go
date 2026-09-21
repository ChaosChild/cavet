package projection

import (
	"encoding/json"
	"fmt"
)

// ParseTrivyJSON parses `trivy fs --format json` output from the pinned engine
// trivy 0.74.0 (route A: the fs scan switched from SARIF to JSON so the
// per-package Dev flag becomes reachable). Identity inputs (RuleID, CWE,
// Snippet) must reproduce exactly what the SARIF path produced for the same
// scan: the spike capture in testdata/trivy-fs.json / trivy-fs.sarif is the
// byte-level contract, and TestTrivyJSONIdentityParityWithSARIF enforces it in
// CI forever:
//
//   - trivy 0.74.0 fs SARIF carries zero CWE tags and zero region snippets for
//     every class, so identity is (RuleID, "", ""). The JSON's richer fields
//     (CweIDs, Secrets[].Match, CauseMetadata.Code) are deliberately ignored
//     here; adopting any of them would re-roll every trivy-fs fingerprint.
//   - rule ids are byte-identical across both formats (trivy emits bare
//     DS-xxxx misconfig ids, not AVD-DS-xxxx).
//
// Dev rides result-level Packages[].Dev, joined to vulnerabilities by
// Vulnerabilities[].PkgID == Packages[].ID, falling back to
// PkgName+InstalledVersion == Name+Version when a PkgID is absent.
func ParseTrivyJSON(data []byte, target string) ([]Finding, error) {
	var doc struct {
		Results []struct {
			Target          string `json:"Target"`
			Class           string `json:"Class"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgID            string `json:"PkgID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
				// CweIDs deliberately unread: see the identity contract above.
			} `json:"Vulnerabilities"`
			Misconfigurations []struct {
				ID       string `json:"ID"`
				Title    string `json:"Title"`
				Severity string `json:"Severity"`
				// Code deliberately unread: see the identity contract above.
				CauseMetadata struct {
					StartLine int `json:"StartLine"`
				} `json:"CauseMetadata"`
			} `json:"Misconfigurations"`
			Secrets []struct {
				RuleID   string `json:"RuleID"`
				Title    string `json:"Title"`
				Severity string `json:"Severity"`
				// The secret row's location field in the pinned capture is
				// StartLine on the secret entry itself; Match and Code are
				// deliberately unread. Absent StartLine degrades to 1, the
				// value trivy's SARIF writer defaults to.
				StartLine int `json:"StartLine"`
			} `json:"Secrets"`
			Packages []struct {
				ID        string `json:"ID"`
				Name      string `json:"Name"`
				Version   string `json:"Version"`
				Dev       bool   `json:"Dev"`
				Locations []struct {
					StartLine int `json:"StartLine"`
				} `json:"Locations"`
			} `json:"Packages"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("trivy: invalid JSON: %w", err)
	}

	var out []Finding
	for _, res := range doc.Results {
		// Package identity -> (dev flag, lockfile line). The line join is how
		// vuln rows reproduce the SARIF startLine (the package's lockfile
		// location); fallback 1 matches trivy's writer default.
		type pkgInfo struct {
			dev       bool
			startLine int
		}
		pkgs := map[string]pkgInfo{}
		for _, p := range res.Packages {
			info := pkgInfo{dev: p.Dev}
			if len(p.Locations) > 0 {
				info.startLine = p.Locations[0].StartLine
			}
			pkgs[p.ID] = info
			pkgs[p.Name+"\x00"+p.Version] = info // fallback key when PkgID is absent
		}
		lookupPkg := func(pkgID, name, version string) pkgInfo {
			if info, ok := pkgs[pkgID]; ok {
				return info
			}
			return pkgs[name+"\x00"+version]
		}

		for _, v := range res.Vulnerabilities {
			line := 1
			if info := lookupPkg(v.PkgID, v.PkgName, v.InstalledVersion); info.startLine > 0 {
				line = info.startLine
			}
			out = append(out, Finding{
				Scanner:  "trivy",
				RuleID:   v.VulnerabilityID,
				CWE:      "", // deliberate: trivy fs SARIF has no CWE tags
				Severity: NormalizeSeverity("trivy", v.Severity),
				Path:     stripTarget(res.Target, target),
				Line:     line,
				Desc:     oneLine(v.Title),
				Dev:      lookupPkg(v.PkgID, v.PkgName, v.InstalledVersion).dev,
			})
		}
		for _, m := range res.Misconfigurations {
			line := m.CauseMetadata.StartLine
			if line < 1 {
				line = 1 // e.g. DS-0026 has no JSON line while SARIF shows 1
			}
			out = append(out, Finding{
				Scanner:  "trivy",
				RuleID:   m.ID,
				Severity: NormalizeSeverity("trivy", m.Severity),
				Path:     stripTarget(res.Target, target),
				Line:     line,
				Desc:     oneLine(m.Title),
			})
		}
		for _, sec := range res.Secrets {
			line := sec.StartLine
			if line < 1 {
				line = 1
			}
			out = append(out, Finding{
				Scanner:  "trivy",
				RuleID:   sec.RuleID,
				Severity: NormalizeSeverity("trivy", sec.Severity),
				Path:     stripTarget(res.Target, target),
				Line:     line,
				Desc:     oneLine(sec.Title),
				Snippet:  "", // deliberate: trivy fs SARIF has no snippets
			})
		}
	}
	return out, nil
}
