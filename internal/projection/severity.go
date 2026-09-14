package projection

import "strings"

// rawSeverity pulls each emitter's native severity signal (cli-spec §7).
// Gitleaks emits none; Trivy carries it in the rule tags; Opengrep in the
// rule's default configuration level.
func rawSeverity(scanner string, rule sarifRule) string {
	switch scanner {
	case "trivy", "trivy-image": // image scans emit the same rule tags
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
// committed credential is high by definition. Checkov findings are medium:
// its SARIF marks every failed check "error" regardless of the check's own
// severity, so no native signal exists, and a blanket high would inflate the
// counts while info would bury failed-policy findings.
func NormalizeSeverity(scanner, raw string) string {
	if scanner == "gitleaks" {
		return "high"
	}
	if scanner == "checkov" {
		return "medium"
	}
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
	return "info"
}
