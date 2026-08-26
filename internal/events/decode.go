package events

import (
	"encoding/json"
	"fmt"
	"time"
)

type decoded struct {
	TS          time.Time       `json:"ts"`
	V           int             `json:"v"`
	Event       Kind            `json:"event"`
	Fingerprint string          `json:"fingerprint"`
	Actor       Actor           `json:"actor"`
	Phase       Phase           `json:"phase"`
	Engine      string          `json:"engine"`
	Data        json.RawMessage `json:"data"`
}

// Decode parses one log line into an Event, enforcing the schema gates of
// artefacts §10: higher versions are rejected loudly, envelope values outside
// the closed sets are malformed, and unknown event kinds are preserved
// verbatim so an old binary never destroys what a new one wrote.
//
// The data section is kept byte-for-byte, so Canonical of a decoded event
// matches what was written.
func Decode(line []byte) (Event, error) {
	var d decoded
	if err := json.Unmarshal(line, &d); err != nil {
		return Event{}, err
	}
	if d.V > SchemaVersion {
		return Event{}, fmt.Errorf("log schema v%d newer than binary v%d; upgrade cavet",
			d.V, SchemaVersion)
	}
	switch d.Actor {
	case ActorAgent, ActorOperator:
	default:
		return Event{}, fmt.Errorf("bad actor %q", d.Actor)
	}
	switch d.Phase {
	case PhaseDesign, PhaseBuild, PhaseTest, PhaseDeploy:
	default:
		return Event{}, fmt.Errorf("bad phase %q", d.Phase)
	}
	if d.Engine == "" {
		return Event{}, fmt.Errorf("engine digest required (artefacts §2.1)")
	}
	if len(d.Data) == 0 {
		return Event{}, fmt.Errorf("data required")
	}
	if isKnownKind(d.Event) && fingerprintRequired(d.Event) && !validFp(d.Fingerprint) {
		return Event{}, fmt.Errorf("%s: malformed fingerprint", d.Event)
	}
	return Event{TS: d.TS, V: d.V, Kind: d.Event, Fingerprint: d.Fingerprint,
		Actor: d.Actor, Phase: d.Phase, Engine: d.Engine, raw: []byte(d.Data)}, nil
}

// Payload returns the typed payload for known kinds, nil for unknown kinds.
// Events reconstructed from disk decode lazily on first access.
func (e *Event) Payload() Data {
	if e.payload != nil || len(e.raw) == 0 {
		return e.payload
	}
	switch e.Kind {
	case Detected:
		var d DetectedData
		if json.Unmarshal(e.raw, &d) != nil {
			return nil
		}
		e.payload = d
	case Triaged:
		var d TriagedData
		if json.Unmarshal(e.raw, &d) != nil {
			return nil
		}
		e.payload = d
	case Surfaced:
		var d SurfacedData
		if json.Unmarshal(e.raw, &d) != nil {
			return nil
		}
		e.payload = d
	case Remediated:
		var d RemediatedData
		if json.Unmarshal(e.raw, &d) != nil {
			return nil
		}
		e.payload = d
	case Suppressed:
		var d SuppressedData
		if json.Unmarshal(e.raw, &d) != nil {
			return nil
		}
		e.payload = d
	case Deferred:
		var d DeferredData
		if json.Unmarshal(e.raw, &d) != nil {
			return nil
		}
		e.payload = d
	case Raised:
		var d RaisedData
		if json.Unmarshal(e.raw, &d) != nil {
			return nil
		}
		e.payload = d
	case Resolved:
		var d ResolvedData
		if json.Unmarshal(e.raw, &d) != nil {
			return nil
		}
		e.payload = d
	case Rebaselined:
		var d RebaselinedData
		if json.Unmarshal(e.raw, &d) != nil {
			return nil
		}
		e.payload = d
	}
	return e.payload
}

func isKnownKind(k Kind) bool {
	switch k {
	case Detected, Triaged, Surfaced, Remediated, Suppressed, Deferred,
		Raised, Resolved, Rebaselined:
		return true
	}
	return false
}
