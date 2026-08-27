package lookup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// RuleEntry is one scanner-rule record for local, offline, version-exact
// lookup (spec §5.3: rule metadata ships in the engine image; here it is
// extracted from the opengrep SARIF we already hold rather than a separate
// container exec — deviation cli-spec §16.21).
type RuleEntry struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	CWE     string `json:"cwe"`
	URL     string `json:"url"`
}

// ExtractRules pulls the rule catalogue out of an opengrep SARIF document.
// The document embeds metadata for every rule it loaded, matched or not.
func ExtractRules(sarif []byte) []RuleEntry {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID                   string `json:"id"`
						ShortDescription     struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						HelpURI    string   `json:"helpUri"`
						Properties struct {
							Tags []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if json.Unmarshal(sarif, &doc) != nil {
		return nil
	}
	var out []RuleEntry
	for _, run := range doc.Runs {
		for _, r := range run.Tool.Driver.Rules {
			e := RuleEntry{ID: r.ID, Message: r.ShortDescription.Text, URL: r.HelpURI}
			for _, tag := range r.Properties.Tags {
				if strings.HasPrefix(tag, "CWE-") {
					e.CWE = strings.TrimSuffix(tag, ":")
					break
				}
			}
			out = append(out, e)
		}
	}
	return out
}

// WriteRuleCatalog persists the catalogue next to the advisory cache.
func WriteRuleCatalog(path string, rules []RuleEntry) error {
	if len(rules) == 0 {
		return nil
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// FileCatalog resolves rule ids from the extracted catalogue.
type FileCatalog struct {
	path string
	m    map[string]RuleEntry
}

// NewFileCatalog loads rules.json lazily on first lookup.
func NewFileCatalog(path string) *FileCatalog { return &FileCatalog{path: path} }

func (f *FileCatalog) load() {
	if f.m != nil {
		return
	}
	f.m = map[string]RuleEntry{}
	b, err := os.ReadFile(f.path)
	if err != nil {
		return
	}
	var rules []RuleEntry
	if json.Unmarshal(b, &rules) == nil {
		for _, r := range rules {
			f.m[r.ID] = r
		}
	}
}

// Lookup implements RuleCatalog.
func (f *FileCatalog) Lookup(ruleID string) (summary, cwe, url string, ok bool) {
	f.load()
	// Rule ids arrive with the config-path prefix (opt.opengrep-rules.…);
	// match on the last path segments too.
	r, ok := f.m[ruleID]
	if !ok {
		for _, e := range f.m {
			if strings.HasSuffix(e.ID, ruleID) || strings.HasSuffix(ruleID, e.ID) {
				r, ok = e, true
				break
			}
		}
	}
	if !ok {
		return "", "", "", false
	}
	return r.Message, r.CWE, r.URL, true
}

// CatalogPath is where the scan pipeline drops the extracted catalogue.
func CatalogPath(cacheDir string) string { return filepath.Join(cacheDir, "rules.json") }
