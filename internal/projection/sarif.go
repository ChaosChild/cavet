// Package projection parses scanner SARIF into a finding model, normalises
// severities, and merges across scanners with pre-fingerprint secret collapse
// (cli-spec §§7–9; SPECIFICATION.md §3.3, §4). Raw SARIF never reaches the
// model; this is the compact projection layer.
package projection

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Finding is one scanner observation, post-parse and pre-merge.
type Finding struct {
	Scanner  string
	RuleID   string
	CWE      string // empty unless the scanner supplies one
	Severity string // already normalised
	Path     string // repo-relative, forward slashes
	Line     int
	Desc     string // one line; renderer truncates further
	Snippet  string // matched-span text; feeds fingerprinting and secret collapse
}

type sarifDoc struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	} `json:"runs"`
}

type sarifRule struct {
	ID                   string `json:"id"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	Properties struct {
		Tags []string `json:"tags"`
	} `json:"properties"`
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Message   struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
				Snippet   struct {
					Text string `json:"text"`
				} `json:"snippet"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

// Parse reads one scanner's SARIF and returns its findings. Rules are resolved
// per result by ruleIndex where present (Trivy) or by rule id otherwise
// (Gitleaks, Opengrep). A malformed result drops its row with a warning naming
// the scanner — never a hard failure (cli-spec §9). The target prefix (the
// container path scanned, e.g. /workspace or /scan/3) is stripped from
// absolute paths so results come back repo-relative.
func Parse(scanner string, data []byte, target string) ([]Finding, []string, error) {
	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: invalid SARIF: %w", scanner, err)
	}
	var out []Finding
	var warns []string
	for _, run := range doc.Runs {
		rules := run.Tool.Driver.Rules
		byID := make(map[string]int, len(rules))
		for i, r := range rules {
			if _, seen := byID[r.ID]; !seen {
				byID[r.ID] = i
			}
		}
		for _, res := range run.Results {
			f, warn := parseResult(scanner, target, rules, byID, res)
			if warn != "" {
				warns = append(warns, warn)
				continue
			}
			out = append(out, f)
		}
	}
	return out, warns, nil
}

func parseResult(scanner, target string, rules []sarifRule, byID map[string]int, res sarifResult) (Finding, string) {
	if len(res.Locations) == 0 {
		return Finding{}, fmt.Sprintf("%s: rule %s has no location, row dropped", scanner, res.RuleID)
	}
	loc := res.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI == "" || loc.Region.StartLine < 1 {
		return Finding{}, fmt.Sprintf("%s: rule %s has an incomplete location, row dropped", scanner, res.RuleID)
	}
	var rule sarifRule
	if res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(rules) {
		rule = rules[*res.RuleIndex]
	} else if i, ok := byID[res.RuleID]; ok {
		rule = rules[i]
	}
	// A missing rule degrades to empty metadata, never a failure (cli-spec §9).
	return Finding{
		Scanner:  scanner,
		RuleID:   res.RuleID,
		CWE:      cweOf(rule),
		Severity: NormalizeSeverity(scanner, rawSeverity(scanner, rule)),
		Path:     stripTarget(loc.ArtifactLocation.URI, target),
		Line:     loc.Region.StartLine,
		Desc:     oneLine(descriptionFor(scanner, res, rule)),
		Snippet:  loc.Region.Snippet.Text,
	}, ""
}

// stripTarget rewrites a container-absolute path back to repo-relative.
// Already-relative paths pass through unchanged.
func stripTarget(uri, target string) string {
	uri = strings.ReplaceAll(uri, "\\", "/")
	if target != "" && strings.HasPrefix(uri, target+"/") {
		return uri[len(target)+1:]
	}
	return strings.TrimPrefix(uri, "/")
}

// descriptionFor picks the most informative one-line text per emitter.
func descriptionFor(scanner string, res sarifResult, rule sarifRule) string {
	msg := res.Message.Text
	switch scanner {
	case "trivy":
		if rule.ShortDescription.Text != "" {
			return rule.ShortDescription.Text
		}
		if i := strings.Index(msg, "\n"); i >= 0 {
			return msg[:i]
		}
		return msg
	default: // gitleaks, opengrep: the result message carries the finding text
		if msg != "" {
			return msg
		}
		return rule.ShortDescription.Text
	}
}

// cweOf extracts the CWE id from a rule's tags ("CWE-89: ..." → "CWE-89").
func cweOf(rule sarifRule) string {
	for _, tag := range rule.Properties.Tags {
		if strings.HasPrefix(tag, "CWE-") {
			if i := strings.Index(tag, ":"); i > 0 {
				return tag[:i]
			}
			return tag
		}
	}
	return ""
}

// oneLine collapses whitespace so descriptions stay table-safe.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
