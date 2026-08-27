package events

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// NewDetected records a scanner finding on first sight (spec §3.2).
func NewDetected(ts time.Time, actor Actor, phase Phase, engine, fp string, d DetectedData) (Event, error) {
	if d.Rule == "" || d.Path == "" || d.Scanner == "" || !validSeverity(d.Severity) || d.Line < 1 {
		return Event{}, fmt.Errorf("detected: incomplete payload %+v", d)
	}
	return build(ts, actor, phase, engine, fp, d)
}

// NewTriaged records a confirm/dismiss verdict; reason and confidence are
// mandatory so the difference between verdicts is preserved (spec §6).
func NewTriaged(ts time.Time, actor Actor, phase Phase, engine, fp string, d TriagedData) (Event, error) {
	if d.Reason == "" {
		return Event{}, fmt.Errorf("triaged: reason required")
	}
	if d.Verdict != VerdictConfirmed && d.Verdict != VerdictDismissed {
		return Event{}, fmt.Errorf("triaged: verdict %q", d.Verdict)
	}
	if d.Confidence != ConfidenceHigh && d.Confidence != ConfidenceLow {
		return Event{}, fmt.Errorf("triaged: confidence %q", d.Confidence)
	}
	return build(ts, actor, phase, engine, fp, d)
}

func NewSurfaced(ts time.Time, actor Actor, phase Phase, engine, fp string, d SurfacedData) (Event, error) {
	switch d.Context {
	case ContextPreCommit, ContextDispatch, ContextPosture:
	default:
		return Event{}, fmt.Errorf("surfaced: context %q", d.Context)
	}
	return build(ts, actor, phase, engine, fp, d)
}

func NewRemediated(ts time.Time, actor Actor, phase Phase, engine, fp, reason string) (Event, error) {
	return newReasoned(Remediated, ts, actor, phase, engine, fp, reason)
}

func NewSuppressed(ts time.Time, actor Actor, phase Phase, engine, fp, reason string) (Event, error) {
	return newReasoned(Suppressed, ts, actor, phase, engine, fp, reason)
}

func NewDeferred(ts time.Time, actor Actor, phase Phase, engine, fp, reason string) (Event, error) {
	return newReasoned(Deferred, ts, actor, phase, engine, fp, reason)
}

// NewRaised opens an item. The envelope carries no fingerprint; for
// verification items it travels in data (artefacts §2.1).
func NewRaised(ts time.Time, actor Actor, phase Phase, engine string, d RaisedData) (Event, error) {
	if d.Question == "" {
		return Event{}, fmt.Errorf("raised: question required")
	}
	switch d.Kind {
	case ItemDesign:
		if d.Fingerprint != "" {
			return Event{}, fmt.Errorf("raised design: fingerprint forbidden")
		}
	case ItemVerification:
		if !validFp(d.Fingerprint) {
			return Event{}, fmt.Errorf("raised verification: fingerprint required")
		}
	default:
		return Event{}, fmt.Errorf("raised: kind %q", d.Kind)
	}
	return build(ts, actor, phase, engine, "", d)
}

// NewResolved closes the open item named by d.Item.
func NewResolved(ts time.Time, actor Actor, phase Phase, engine string, d ResolvedData) (Event, error) {
	if !validItemID(d.Item) {
		return Event{}, fmt.Errorf("resolved: item id required (it-xxxxxxxx)")
	}
	if d.Answer == "" {
		return Event{}, fmt.Errorf("resolved: answer required")
	}
	return build(ts, actor, phase, engine, "", d)
}

// NewRebaselined records an engine-image transition. Digests may be empty:
// from_digest always is on the initial baseline (cli-spec §5), and to_digest
// is when development runs an unpushed local image. The reason is mandatory.
func NewRebaselined(ts time.Time, actor Actor, phase Phase, engine string, d RebaselinedData) (Event, error) {
	if d.Reason == "" {
		return Event{}, fmt.Errorf("rebaselined: reason required")
	}
	return build(ts, actor, phase, engine, "", d)
}

func newReasoned(k Kind, ts time.Time, actor Actor, phase Phase, engine, fp, reason string) (Event, error) {
	if reason == "" {
		return Event{}, fmt.Errorf("%s: reason required", k)
	}
	var d Data
	switch k {
	case Remediated:
		d = RemediatedData{Reason: reason}
	case Suppressed:
		d = SuppressedData{Reason: reason}
	case Deferred:
		d = DeferredData{Reason: reason}
	default:
		return Event{}, fmt.Errorf("kind %s not reasoned", k)
	}
	return build(ts, actor, phase, engine, fp, d)
}

func build(ts time.Time, actor Actor, phase Phase, engine, fp string, d Data) (Event, error) {
	e := Event{TS: ts.UTC(), V: SchemaVersion, Kind: d.dataKind(),
		Fingerprint: fp, Actor: actor, Phase: phase, Engine: engine, payload: d}
	switch actor {
	case ActorAgent, ActorOperator:
	default:
		return Event{}, fmt.Errorf("%s: bad actor %q", e.Kind, actor)
	}
	switch phase {
	case PhaseDesign, PhaseBuild, PhaseTest, PhaseDeploy:
	default:
		return Event{}, fmt.Errorf("%s: bad phase %q", e.Kind, phase)
	}
	if engine == "" {
		return Event{}, fmt.Errorf("%s: engine digest required (artefacts §2.1)", e.Kind)
	}
	if fingerprintRequired(e.Kind) && fp == "" {
		return Event{}, fmt.Errorf("%s: fingerprint required (artefacts §2.1)", e.Kind)
	}
	if fp != "" && !validFp(fp) {
		return Event{}, fmt.Errorf("%s: malformed fingerprint %q", e.Kind, fp)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return Event{}, err
	}
	e.raw = raw
	return e, nil
}

// fingerprintRequired reports whether the envelope carries a fingerprint for k
// (artefacts §2.1: absent on raised, resolved, rebaselined).
func fingerprintRequired(k Kind) bool {
	switch k {
	case Raised, Resolved, Rebaselined:
		return false
	}
	return true
}

func validFp(fp string) bool {
	return len(fp) == 64 && isLowerHex(fp)
}

// validItemID matches the content-derived item id shape: it- + 8 lowercase hex
// (artefacts §6.2).
func validItemID(id string) bool {
	return len(id) == 11 && strings.HasPrefix(id, "it-") && isLowerHex(id[3:])
}

func isLowerHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func validSeverity(s Severity) bool {
	switch s {
	case SevCritical, SevHigh, SevMedium, SevLow, SevInfo:
		return true
	}
	return false
}
