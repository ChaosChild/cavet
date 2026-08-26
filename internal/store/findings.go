package store

import (
	"time"

	"github.com/ChaosChild/cavet/internal/events"
)

// State types mirror artefacts-spec.md §9. All three state files are derived:
// findings and items regenerate from the log, baseline is preserved across
// rebuilds (it is written by init/rebaseline from a scan, §6.3).

type Location struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

type Verdict struct {
	Verdict    string          `json:"verdict"`
	Confidence string          `json:"confidence"`
	Reason     string          `json:"reason"`
	Sources    []events.Source `json:"sources,omitempty"`
	At         time.Time       `json:"at"`
	By         string          `json:"by"`
}

type Finding struct {
	Fingerprint        string     `json:"fingerprint"`
	DisplayID          string     `json:"display_id"`
	RuleKey            string     `json:"rule_key"`
	RuleID             string     `json:"rule_id"`
	OriginatingScanner string     `json:"originating_scanner"`
	AlsoDetectedBy     []string   `json:"also_detected_by,omitempty"`
	Secret             bool       `json:"secret"`
	CollapsedWith      []string   `json:"collapsed_with,omitempty"`
	Severity           string     `json:"severity"`
	Description        string     `json:"description"`
	Locations          []Location `json:"locations"`
	DetectedAt         time.Time  `json:"detected_at"`
	LastSeen           time.Time  `json:"last_seen"`
	Status             string     `json:"status"` // open|confirmed|dismissed|deferred|suppressed
	Verdict            *Verdict   `json:"verdict"`
	InBaseline         bool       `json:"in_baseline"`
}

type Item struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Question    string    `json:"question"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	RaisedAt    time.Time `json:"raised_at"`
	RaisedBy    string    `json:"raised_by"`
}

type Baseline struct {
	EngineDigest string    `json:"engine_digest"`
	CreatedAt    time.Time `json:"created_at"`
	Fingerprints []string  `json:"fingerprints"`
}

// State is the replay result. The unexported indexes serve the fold only and
// are never marshalled.
type State struct {
	RebuiltAt time.Time  `json:"rebuilt_at"`
	Findings  []*Finding `json:"findings"`
	Items     []Item     `json:"items"`
	Baseline  Baseline   `json:"baseline"`

	findingsByFP map[string]*Finding
	itemsByID    map[string]bool
}
