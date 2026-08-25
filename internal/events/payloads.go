package events

// Data is the closed set of payload types. Each payload knows its kind, so an
// Event's payload can never disagree with its envelope (artefacts §3).
type Data interface{ dataKind() Kind }

type Source struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type DetectedData struct {
	Rule           string   `json:"rule"`
	Severity       Severity `json:"severity"`
	Path           string   `json:"path"`
	Line           int      `json:"line"`
	Description    string   `json:"description"`
	Scanner        string   `json:"scanner"`
	AlsoDetectedBy []string `json:"also_detected_by,omitempty"`
}

type TriagedData struct {
	Verdict    Verdict    `json:"verdict"`
	Confidence Confidence `json:"confidence"`
	Reason     string     `json:"reason"`
	Sources    []Source   `json:"sources,omitempty"`
}

type SurfacedData struct {
	Context SurfaceContext `json:"context"`
}

type RemediatedData struct {
	Reason string `json:"reason"`
}

type SuppressedData struct {
	Reason string `json:"reason"`
}

type DeferredData struct {
	Reason string `json:"reason"`
}

type RaisedData struct {
	Kind        ItemKind `json:"kind"`
	Question    string   `json:"question"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

type ResolvedData struct {
	Item    string   `json:"item"`
	Answer  string   `json:"answer"`
	Sources []Source `json:"sources,omitempty"`
}

type RebaselinedData struct {
	FromDigest string `json:"from_digest"`
	ToDigest   string `json:"to_digest"`
	Reason     string `json:"reason"`
}

func (DetectedData) dataKind() Kind    { return Detected }
func (TriagedData) dataKind() Kind     { return Triaged }
func (SurfacedData) dataKind() Kind    { return Surfaced }
func (RemediatedData) dataKind() Kind  { return Remediated }
func (SuppressedData) dataKind() Kind  { return Suppressed }
func (DeferredData) dataKind() Kind    { return Deferred }
func (RaisedData) dataKind() Kind      { return Raised }
func (ResolvedData) dataKind() Kind    { return Resolved }
func (RebaselinedData) dataKind() Kind { return Rebaselined }
