package lookup

import (
	"context"
	"os"
)

// NVD — supplementary CVSS vectors (spec §5.3). Optional key via NVD_API_KEY;
// works keyless at lower rate limits.

type NVD struct {
	Base string
	Key  string
}

func NewNVD() *NVD {
	return &NVD{Base: "https://services.nvd.nist.gov/rest/json/cves/2.0", Key: os.Getenv("NVD_API_KEY")}
}

type nvdResp struct {
	Vulnerabilities []struct {
		CVE struct {
			ID string `json:"id"`
			Metrics struct {
				CvssMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Vector returns the CVSS v3.1 base score and vector for a CVE.
func (n *NVD) Vector(ctx context.Context, cve string) (score float64, vector string, err error) {
	header := map[string]string{}
	if n.Key != "" {
		header["apiKey"] = n.Key
	}
	var r nvdResp
	if err := getJSON(ctx, n.Base+"?cveId="+cve, header, &r); err != nil {
		return 0, "", err
	}
	for _, v := range r.Vulnerabilities {
		for _, m := range v.CVE.Metrics.CvssMetricV31 {
			return m.CVSSData.BaseScore, m.CVSSData.VectorString, nil
		}
	}
	return 0, "", &ErrDegraded{Source: "nvd", Err: errNoScore(cve)}
}
