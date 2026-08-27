package describe

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ChaosChild/cavet/internal/events"
)

func TestContractShape(t *testing.T) {
	b, err := JSON("0.1.0", "core", "sha256:abc", "/harness/skills")
	if err != nil {
		t.Fatal(err)
	}
	var c Contract
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if c.CavetVersion != "0.1.0" || c.LogSchemaVersion != events.SchemaVersion {
		t.Fatalf("version fields wrong: %+v", c)
	}
	if len(c.Skills) != 6 || !strings.HasPrefix(c.Skills[0].RecommendedPath, "/harness/skills/") {
		t.Fatalf("skills dir override failed: %+v", c.Skills)
	}
	if c.Engine.Image != "ghcr.io/chaoschild/cavet-engine" || c.Engine.Digest != "sha256:abc" {
		t.Fatalf("engine block wrong: %+v", c.Engine)
	}
	if c.Subagent.Name != "cavet-security" || len(c.Subagent.Tools) != 2 {
		t.Fatalf("subagent block wrong: %+v", c.Subagent)
	}
	if len(c.Commands) != 9 || len(c.Triggers) != 1 {
		t.Fatalf("commands/triggers wrong: %d %d", len(c.Commands), len(c.Triggers))
	}
	for _, name := range []string{"cavet-design", "cavet-triage", "cavet-deployment"} {
		found := false
		for _, s := range c.Skills {
			if s.Name == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("skill %s missing", name)
		}
	}
}
