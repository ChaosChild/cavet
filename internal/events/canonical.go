package events

import (
	"encoding/json"
	"time"
)

// envelope is the on-disk shape of an event (artefacts §2.1). Field order is
// the marshalled order — deterministic, which replay ordering depends on (§6.1).
type envelope struct {
	TS          string          `json:"ts"`
	V           int             `json:"v"`
	Kind        Kind            `json:"event"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Actor       Actor           `json:"actor"`
	Phase       Phase           `json:"phase"`
	Engine      string          `json:"engine"`
	Data        json.RawMessage `json:"data"`
}

// Canonical returns the deterministic encoding of e: ts pinned to RFC 3339 UTC
// seconds, payload bytes exactly as fixed at construction. It is the input to
// replay ordering and item-id derivation (artefacts §§3, 6.1).
func Canonical(e Event) []byte {
	env := envelope{
		TS: e.TS.UTC().Format(time.RFC3339), V: e.V, Kind: e.Kind,
		Fingerprint: e.Fingerprint, Actor: e.Actor, Phase: e.Phase,
		Engine: e.Engine, Data: e.raw,
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil
	}
	return out
}
