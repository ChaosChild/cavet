package projection

import (
	"encoding/json"
	"strings"
)

// TrivySARIFRun renders parsed trivy fs findings as a one-run SARIF document.
// The fs scan reads trivy JSON (route A), so trivy no longer emits SARIF
// itself; reports/latest.sarif stays SARIF (SPECIFICATION.md §4) and trivy's
// contribution to the merged report is projected here from the parsed
// findings. Rules come from unique RuleIDs in first-seen order, severity rides
// defaultConfiguration.level plus the raw token in properties.tags (the same
// signal rawSeverity reads), CWE appears as a tag only when a scanner supplied
// one, and dev rows carry properties.dev so CI consumers see the marker too.
func TrivySARIFRun(fs []Finding) ([]byte, error) {
	type ruleOut struct {
		ID                   string `json:"id"`
		DefaultConfiguration struct {
			Level string `json:"level"`
		} `json:"defaultConfiguration"`
		Properties struct {
			Tags []string `json:"tags,omitempty"`
		} `json:"properties"`
	}
	type resultOut struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		} `json:"locations"`
		Properties *struct {
			Dev bool `json:"dev,omitempty"`
		} `json:"properties,omitempty"`
	}
	type runOut struct {
		Tool struct {
			Driver struct {
				Name    string    `json:"name"`
				Version string    `json:"version"`
				Rules   []ruleOut `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []resultOut `json:"results"`
	}

	var run runOut
	run.Tool.Driver.Name = "Trivy"
	run.Tool.Driver.Version = "0.74.0" // the pinned engine these findings were parsed from
	// Empty slices, not nil: a clean scan (zero findings, the common case)
	// must marshal "rules":[] / "results":[], never null, which strict SARIF
	// consumers such as GitHub code scanning reject.
	run.Tool.Driver.Rules = []ruleOut{}
	run.Results = []resultOut{}

	rules := map[string]bool{}
	for _, f := range fs {
		level := sarifLevel(f.Severity)
		if !rules[f.RuleID] {
			rules[f.RuleID] = true
			r := ruleOut{ID: f.RuleID}
			r.DefaultConfiguration.Level = level
			r.Properties.Tags = append([]string{"security"}, sarifTags(f)...)
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, r)
		}
		var res resultOut
		res.RuleID = f.RuleID
		res.Level = level
		res.Message.Text = f.Desc
		var loc struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		}
		loc.PhysicalLocation.ArtifactLocation.URI = f.Path
		loc.PhysicalLocation.Region.StartLine = f.Line
		res.Locations = append(res.Locations, loc)
		if f.Dev {
			res.Properties = &struct {
				Dev bool `json:"dev,omitempty"`
			}{Dev: true}
		}
		run.Results = append(run.Results, res)
	}

	doc := struct {
		Version string   `json:"version"`
		Schema  string   `json:"$schema"`
		Runs    []runOut `json:"runs"`
	}{"2.1.0", "https://json.schemastore.org/sarif-2.1.0.json", []runOut{run}}
	return json.Marshal(doc)
}

// sarifLevel maps cavet's normalised severity onto SARIF levels, matching the
// mapping trivy's own SARIF writer used (CRITICAL/HIGH→error, MEDIUM→warning,
// LOW→note).
func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// sarifTags keeps the projected run round-trippable through the SARIF parse:
// the raw severity token first (rawSeverity reads the first severity tag),
// then CWE when one exists.
func sarifTags(f Finding) []string {
	tags := []string{strings.ToUpper(f.Severity)}
	if f.CWE != "" {
		tags = append(tags, f.CWE)
	}
	return tags
}
