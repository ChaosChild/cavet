package lookup

import (
	"context"
	"strconv"
	"strings"
)

// EPSS — exploitation probability score (spec §5.3). No auth.

type EPSS struct{ Base string }

func NewEPSS() *EPSS { return &EPSS{Base: "https://api.first.org/data/v1"} }

// flexFloat accepts both 0.97 and "0.97" — the EPSS API ships strings
// (measured live).
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" || s == "" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	*f = flexFloat(v)
	return nil
}

type epssResp struct {
	Data []struct {
		CVE        string    `json:"cve"`
		EPSS       flexFloat `json:"epss"`
		Percentile flexFloat `json:"percentile"`
	} `json:"data"`
}

// Score returns the EPSS probability for a CVE (0–1) and its percentile.
func (e *EPSS) Score(ctx context.Context, cve string) (epss, percentile float64, err error) {
	var r epssResp
	if err := getJSON(ctx, e.Base+"/epss?cve="+cve, nil, &r); err != nil {
		return 0, 0, err
	}
	if len(r.Data) == 0 {
		return 0, 0, &ErrDegraded{Source: "epss", Err: errNoScore(cve)}
	}
	return float64(r.Data[0].EPSS), float64(r.Data[0].Percentile), nil
}

type strErr string

func (e strErr) Error() string { return string(e) }

func errNoScore(cve string) error { return strErr("no score for " + cve) }
