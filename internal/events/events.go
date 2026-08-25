// Package events owns every shape in the cavet log: constants, payload structs,
// validating constructors, and the canonical encoding. No raw string literals for
// kinds, verdicts, confidences, severities, phases, or actors may appear outside
// this package (SPECIFICATION.md §10.2, artefacts-spec.md §3).
package events

import "time"

type (
	Actor          string
	Phase          string
	Kind           string
	Verdict        string
	Confidence     string
	ItemKind       string
	Severity       string
	SurfaceContext string
)

const (
	ActorAgent    Actor = "agent"
	ActorOperator Actor = "operator"

	PhaseDesign Phase = "design"
	PhaseBuild  Phase = "build"
	PhaseTest   Phase = "test"
	PhaseDeploy Phase = "deploy"

	Detected    Kind = "detected"
	Triaged     Kind = "triaged"
	Surfaced    Kind = "surfaced"
	Remediated  Kind = "remediated"
	Suppressed  Kind = "suppressed"
	Deferred    Kind = "deferred"
	Raised      Kind = "raised"
	Resolved    Kind = "resolved"
	Rebaselined Kind = "rebaselined"

	VerdictConfirmed Verdict = "confirmed"
	VerdictDismissed Verdict = "dismissed"

	ConfidenceHigh Confidence = "high"
	ConfidenceLow  Confidence = "low"

	ItemDesign       ItemKind = "design"
	ItemVerification ItemKind = "verification"

	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"

	ContextPreCommit SurfaceContext = "pre-commit"
	ContextDispatch  SurfaceContext = "dispatch"
	ContextPosture   SurfaceContext = "posture"
)

// SchemaVersion is stamped on every event (artefacts §10). Readers reject
// higher versions loudly.
const SchemaVersion = 1

// Event is one line of the append-only log. Construct only via the New*
// functions: validation happens at construction and the payload bytes are
// fixed then, so Canonical is stable for replay ordering (artefacts §3).
type Event struct {
	TS          time.Time
	V           int
	Kind        Kind
	Fingerprint string
	Actor       Actor
	Phase       Phase
	Engine      string

	payload Data
	raw     []byte
}
