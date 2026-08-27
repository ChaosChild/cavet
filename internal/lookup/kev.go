package lookup

import (
	"context"
	"encoding/json"
	"strings"
)

// KEV — CISA known-exploited feed. Whole-feed fetch, cached daily (spec §5.3,
// cli-spec §11). No auth.

type KEV struct {
	Base  string
	Cache *Cache
}

func NewKEV(cache *Cache) *KEV {
	return &KEV{Base: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", Cache: cache}
}

const kevCacheID = "kev:feed"

type kevFeed struct {
	Known []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// IsKnown reports whether a CVE is on the list. Feed fetch and parse failures
// degrade to false with no error — unknown is honest, not blocking.
func (k *KEV) IsKnown(ctx context.Context, cve string) bool {
	raw, _, fresh := k.Cache.Read(kevCacheID)
	if raw == nil || !fresh {
		var feed kevFeed
		if err := getJSON(ctx, k.Base, nil, &feed); err != nil {
			return raw != nil && containsCVE(raw, cve) // stale beat, served
		}
		b, err := json.Marshal(feed)
		if err == nil {
			_ = k.Cache.WriteTTL(kevCacheID, b, 24)
		}
		for _, v := range feed.Known {
			if strings.EqualFold(v.CVEID, cve) {
				return true
			}
		}
		return false
	}
	return containsCVE(raw, cve)
}

func containsCVE(feedJSON []byte, cve string) bool {
	var feed kevFeed
	if json.Unmarshal(feedJSON, &feed) != nil {
		return false
	}
	for _, v := range feed.Known {
		if strings.EqualFold(v.CVEID, cve) {
			return true
		}
	}
	return false
}
