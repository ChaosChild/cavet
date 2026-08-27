package projection

import "strings"

// rawSeverity pulls each emitter's native severity signal (cli-spec §7).
// Gitleaks emits none; Trivy carries it in the rule tags; Opengrep in the
// rule's default configuration level.
func rawSeverity(scanner string, rule sarifRule) string {
	switch scanner {
	case "trivy":
		for _, tag := range rule.Properties.Tags {
			switch tag {
			case "CRITICAL", "HIGH", "MEDIUM", "LOW":
				return tag
			}
		}
		return "UNKNOWN"
	case "opengrep":
		return rule.DefaultConfiguration.Level
	default:
		return ""
	}
}

// NormalizeSeverity maps scanner scales onto critical|high|medium|low|info
// (artefacts §2.3). Gitleaks findings are high until triaged otherwise — a
// committed credential is high by definition.
func NormalizeSeverity(scanner, raw string) string {
	switch strings.ToLower(raw) {
	case "critical":
		return "critical"
	case "high", "error":
		return "high"
	case "medium", "warning":
		return "medium"
	case "low":
		return "low"
	case "info", "note", "unknown":
		return "info"
	}
	if scanner == "gitleaks" {
		return "high"
	}
	return "info"
}
