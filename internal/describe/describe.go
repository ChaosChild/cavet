// Package describe emits the machine contract for third-party installers:
// skill paths, subagent allowlists, trigger commands, engine digest, version
// metadata (cli-spec §12). Schema additions are additive-only; removals bump
// cavet_version major.
package describe

import (
	"encoding/json"

	"github.com/ChaosChild/cavet/internal/events"
)

type Skill struct {
	Name            string `json:"name"`
	Phase           string `json:"phase"`
	RecommendedPath string `json:"recommended_path"`
}

type Engine struct {
	Image   string `json:"image"`
	Variant string `json:"variant"`
	Digest  string `json:"digest"`
}

type Subagent struct {
	Name       string   `json:"name"`
	Tools      []string `json:"tools"`
	Definition string   `json:"definition"`
}

type Trigger struct {
	Name           string `json:"name"`
	InstallCommand string `json:"install_command"`
	Invocation     string `json:"invocation"`
}

type Contract struct {
	CavetVersion     string    `json:"cavet_version"`
	LogSchemaVersion int       `json:"log_schema_version"`
	Engine           Engine    `json:"engine"`
	Skills           []Skill   `json:"skills"`
	Subagent         Subagent  `json:"subagent"`
	Commands         []string  `json:"commands"`
	Triggers         []Trigger `json:"triggers"`
	ConfigKeys       []string  `json:"config_keys"`
}

// Build assembles the contract. skillsDir overrides the recommended_path
// prefix so installers render harness-specific layouts from one source.
func Build(version, variant, digest, skillsDir string) Contract {
	if skillsDir == "" {
		skillsDir = "skills"
	}
	path := func(name string) string { return skillsDir + "/" + name }
	return Contract{
		CavetVersion:     version,
		LogSchemaVersion: events.SchemaVersion,
		Engine:           Engine{Image: "ghcr.io/chaoschild/cavet-engine", Variant: variant, Digest: digest},
		Skills: []Skill{
			{Name: "cavet-design", Phase: "design", RecommendedPath: path("cavet-design")},
			{Name: "cavet-design-review", Phase: "design", RecommendedPath: path("cavet-design-review")},
			{Name: "cavet-triage", Phase: "build", RecommendedPath: path("cavet-triage")},
			{Name: "cavet-secure-coding", Phase: "build", RecommendedPath: path("cavet-secure-coding")},
			{Name: "cavet-supply-chain", Phase: "build", RecommendedPath: path("cavet-supply-chain")},
			{Name: "cavet-deployment", Phase: "deploy", RecommendedPath: path("cavet-deployment")},
		},
		Subagent: Subagent{
			Name:  "cavet-security",
			Tools: []string{"Read", "Shell(cavet *)"},
			Definition: "https://github.com/ChaosChild/cavet/blob/main/subagents/cavet-security.md",
		},
		Commands:   []string{"items", "raise", "resolve", "scan", "triage", "lookup", "defer", "finding", "log"},
		Triggers: []Trigger{{
			Name:           "pre-commit",
			InstallCommand: "cavet init --hooks",
			Invocation:     "cavet scan --staged --context pre-commit",
		}},
		ConfigKeys: []string{"engine.variant", "scan.deep_default", "scanners.checkov"},
	}
}

// JSON renders the contract (describe refuses any other format — cli-spec
// §16.6: nobody asked for a second, human one that would drift).
func JSON(version, variant, digest, skillsDir string) ([]byte, error) {
	b, err := json.MarshalIndent(Build(version, variant, digest, skillsDir), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
