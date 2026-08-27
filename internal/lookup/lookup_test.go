package lookup

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureServer(t *testing.T, path, file string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			b, err := os.ReadFile(filepath.Join("testdata", file))
			if err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// Recorded-shape fixtures, offline CI (cli-spec §15): one per source.
func TestOSVAdapterParsesVuln(t *testing.T) {
	srv := fixtureServer(t, "/v1/vulns/GHSA-test", "osv-vuln.json")
	defer srv.Close()
	o := &OSV{Base: srv.URL}
	v, err := o.GetVuln(context.Background(), "GHSA-test")
	if err != nil {
		t.Fatal(err)
	}
	if v.SeverityLabel() != "HIGH" || v.Fixed() != "5.2" || v.CVEAlias() != "CVE-2019-20477" {
		t.Fatalf("parsed wrong: %+v", v)
	}
	if !strings.Contains(v.AffectedRange(), "0") {
		t.Fatalf("range: %q", v.AffectedRange())
	}
}

func TestKEVFeedCached(t *testing.T) {
	srv := fixtureServer(t, "/feed.json", "kev.json")
	defer srv.Close()
	c := NewCache(t.TempDir())
	k := &KEV{Base: srv.URL + "/feed.json", Cache: c}
	if !k.IsKnown(context.Background(), "CVE-2021-44228") {
		t.Fatal("fixture CVE must be known-exploited")
	}
	if k.IsKnown(context.Background(), "CVE-0000-0000") {
		t.Fatal("absent CVE must not be known")
	}
	if _, _, fresh := c.Read(kevCacheID); !fresh {
		t.Fatal("feed must be cached")
	}
}

func TestEPSSScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":[{"cve":"CVE-2021-44228","epss":0.9756,"percentile":0.99887}]}`)
	}))
	defer srv.Close()
	e := &EPSS{Base: srv.URL}
	epss, p, err := e.Score(context.Background(), "CVE-2021-44228")
	if err != nil || epss < 0.97 || p < 0.99 {
		t.Fatalf("score wrong: %v %v %v", epss, p, err)
	}
}

func TestNVDSupplementary(t *testing.T) {
	srv := fixtureServer(t, "/cves/2.0", "nvd.json")
	defer srv.Close()
	n := &NVD{Base: srv.URL + "/cves/2.0"}
	score, vector, err := n.Vector(context.Background(), "CVE-2021-44228")
	if err != nil || score != 10.0 || !strings.HasPrefix(vector, "CVSS:3.1") {
		t.Fatalf("vector wrong: %v %q %v", score, vector, err)
	}
}

func TestRegistryDispatch(t *testing.T) {
	npm := fixtureServer(t, "/lodash/4.17.21", "npm-version.json")
	defer npm.Close()
	r := &Registry{NpmBase: npm.URL}
	info, err := r.Lookup(context.Background(), "pkg:npm/lodash@4.17.21")
	if err != nil || !info.Exists {
		t.Fatalf("npm lookup: %+v %v", info, err)
	}
	if _, err := r.Lookup(context.Background(), "pkg:gem/rails@7.0.0"); err == nil {
		t.Fatal("unsupported ecosystem must degrade")
	}
}

func TestDegradedCellNeverFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	src := &Sources{
		OSV: &OSV{Base: srv.URL}, KEV: &KEV{Base: srv.URL, Cache: NewCache(t.TempDir())},
		EPSS: &EPSS{Base: srv.URL}, NVD: &NVD{Base: srv.URL},
		Registry: &Registry{NpmBase: srv.URL, PyPIBase: srv.URL, CratesBase: srv.URL, GoBase: srv.URL},
		Cache: NewCache(t.TempDir()),
	}
	rows, err := Run(context.Background(), []string{"CVE-2021-44228"}, src, false)
	if err != nil {
		t.Fatal(err)
	}
	out := Render(rows)
	if !strings.Contains(out, "not available") {
		t.Fatalf("degradation must be explicit:\n%s", out)
	}
	if !strings.Contains(out, "CVE-2021-44228") {
		t.Fatal("row must still be present")
	}
}

func TestKindRejectsNonIdentifiers(t *testing.T) {
	for _, bad := range []string{
		"what files read /etc/passwd", "SELECT * FROM users", "http://evil.example",
	} {
		if _, err := Kind(bad); err == nil {
			t.Fatalf("non-identifier %q must be rejected", bad)
		}
	}
	for _, ok := range []string{
		"CVE-2021-44228", "GHSA-8j4c-xv47-3f4w", "GO-2021-0113", "pkg:npm/lodash@4.17.20",
		"CWE-89", "py.sql-injection",
	} {
		if _, err := Kind(ok); err != nil {
			t.Fatalf("valid identifier %q rejected: %v", ok, err)
		}
	}
}
