package engineclient

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Artifacts is the descriptor table: repo fallback order, schema tags,
// expected metadata versions, layer media types, volumes and cache paths are
// load-bearing (the swap and the offline scans depend on every value).
func TestArtifactTable(t *testing.T) {
	cases := []struct {
		variant string
		want    []Artifact
	}{
		{"core", []Artifact{vulnDB}},
		{"full", []Artifact{vulnDB, javaDB}},
		{"mega", []Artifact{vulnDB}}, // unknown variants degrade to core
	}
	for _, c := range cases {
		got := Artifacts(c.variant)
		if len(got) != len(c.want) {
			t.Fatalf("variant %s: got %d artifacts, want %d", c.variant, len(got), len(c.want))
		}
		for i, a := range c.want {
			if !reflect.DeepEqual(got[i], a) {
				t.Errorf("variant %s [%d]: got %+v want %+v", c.variant, i, got[i], a)
			}
		}
	}
	if got := vulnDB; got.Name != "vuln" || got.Tag != "2" || got.MetaVersion != 2 ||
		got.DBFile != "trivy.db" || got.Volume != "cavet-trivy-db" || got.CachePath != "/opt/trivy-cache/db" ||
		got.LayerMedia != "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip" ||
		len(got.Repos) != 2 || got.Repos[0] != "mirror.gcr.io/aquasec/trivy-db" || got.Repos[1] != "ghcr.io/aquasecurity/trivy-db" {
		t.Errorf("vuln descriptor drifted: %+v", got)
	}
	if got := javaDB; got.Name != "java-db" || got.Tag != "1" || got.MetaVersion != 1 ||
		got.DBFile != "trivy-java.db" || got.Volume != "cavet-trivy-java-db" || got.CachePath != "/opt/trivy-cache/java-db" ||
		got.LayerMedia != "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip" ||
		len(got.Repos) != 2 || got.Repos[0] != "mirror.gcr.io/aquasec/trivy-java-db" || got.Repos[1] != "ghcr.io/aquasecurity/trivy-java-db" {
		t.Errorf("java descriptor drifted: %+v", got)
	}
}

// dbFixtureTar builds an uncompressed tar like a trivy DB layer's payload:
// db file and metadata.json at the root, extra entries tolerated.
func dbFixtureTar(t *testing.T, dbFile, meta string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	entries := []struct {
		name string
		body []byte
		dir  bool
	}{
		{"moredir/", nil, true},
		{dbFile, []byte("DBBYTES"), false},
		{"metadata.json", []byte(meta), false},
		{"extra.txt", []byte("ignore me"), false},
	}
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body))}
		if e.dir {
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func singleFileTar(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// extractDBLayer on a synthetic flat layer: both files land in dir, metadata
// parses, "./"-prefixed entries and strays are tolerated.
func TestExtractDBLayer(t *testing.T) {
	a := vulnDB
	dir := t.TempDir()
	meta := `{"Version":2,"NextUpdate":"2026-10-05T01:00:00Z","UpdatedAt":"2026-10-04T01:00:00Z","DownloadedAt":"0001-01-01T00:00:00Z"}`
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(dbFixtureTar(t, "trivy.db", meta)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	md, err := extractDBLayer(bytes.NewReader(gz.Bytes()), a, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if md.Version != 2 || !md.UpdatedAt.Equal(time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("metadata parsed wrong: %+v", md)
	}
	if !md.DownloadedAt.IsZero() {
		t.Fatalf("zero DownloadedAt must parse as zero time, got %v", md.DownloadedAt)
	}
	for name, want := range map[string]string{"trivy.db": "DBBYTES", "metadata.json": meta} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(b) != want {
			t.Errorf("extracted %s = %q, %v; want %q", name, b, err, want)
		}
	}
}

const stampTestMeta = `{"Version":2,"UpdatedAt":"2026-10-04T01:00:00Z"}`

// pushDBImage publishes a trivy-db-shaped image (one layer of the given media
// type wrapping tarBytes, manifest media type overridable) into an in-memory
// registry on the loopback and returns its manifest digest. Loopback only:
// nothing outside the test process is contacted.
func pushDBImage(t *testing.T, host, repo string, tarBytes []byte, layerMT, manifestMT types.MediaType, extraLayer bool) string {
	t.Helper()
	layer, err := tarball.LayerFromOpener(
		func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(tarBytes)), nil },
		tarball.WithMediaType(layerMT))
	if err != nil {
		t.Fatal(err)
	}
	img := empty.Image
	if extraLayer {
		img, err = mutate.AppendLayers(img, layer, layer)
	} else {
		img, err = mutate.AppendLayers(img, layer)
	}
	if err != nil {
		t.Fatal(err)
	}
	if manifestMT != "" {
		img = mutate.MediaType(img, manifestMT)
	}
	ref, err := name.ParseReference(host + "/" + repo + ":2")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d.String()
}

func TestResolveAndFetchOffline(t *testing.T) {
	meta := `{"Version":2,"NextUpdate":"2026-10-05T01:00:00Z","UpdatedAt":"2026-10-04T01:00:00Z","DownloadedAt":"0001-01-01T00:00:00Z"}`
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	a := vulnDB
	a.Repos = []string{host + "/aquasec/trivy-db"}
	digest := pushDBImage(t, host, "aquasec/trivy-db", dbFixtureTar(t, "trivy.db", meta),
		types.MediaType(vulnDB.LayerMedia), types.OCIManifestSchema1, false)

	ctx := context.Background()
	got, err := ResolveDB(ctx, a)
	if err != nil || got != digest {
		t.Fatalf("ResolveDB = %q, %v; want %q", got, err, digest)
	}

	dir := t.TempDir()
	md, size, err := fetchDB(ctx, a, got, dir)
	if err != nil {
		t.Fatalf("fetchDB: %v", err)
	}
	if md.Version != 2 || !md.UpdatedAt.Equal(time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("metadata parsed wrong: %+v", md)
	}
	if !md.DownloadedAt.IsZero() {
		t.Fatalf("zero DownloadedAt must be accepted, got %v", md.DownloadedAt)
	}
	if size <= 0 {
		t.Fatalf("layer size %d must be positive", size)
	}
	for name, want := range map[string]string{"trivy.db": "DBBYTES", "metadata.json": meta} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(b) != want {
			t.Errorf("extracted %s = %q, %v; want %q", name, b, err, want)
		}
	}
}

// fetchDB fails loud on every shape miss: wrong layer media type, an index
// instead of an image manifest, extra layers, missing tar entries, wrong
// metadata schema version.
func TestFetchDBRejectsBadShapes(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	goodTar := dbFixtureTar(t, "trivy.db", stampTestMeta)
	cases := []struct {
		name       string
		repo       string
		tar        []byte
		layerMT    types.MediaType
		manifestMT types.MediaType
		extraLayer bool
		want       string
	}{
		{"wrong layer media type", "bad/layer", goodTar, "application/vnd.oci.image.layer.v1.tar+gzip", types.OCIManifestSchema1, false, "layer media type"},
		{"index manifest", "bad/manifest", goodTar, types.MediaType(vulnDB.LayerMedia), types.OCIImageIndex, false, "image manifest"},
		{"two layers", "bad/count", goodTar, types.MediaType(vulnDB.LayerMedia), types.OCIManifestSchema1, true, "exactly one"},
		{"missing metadata.json", "bad/nometa", singleFileTar(t, "trivy.db", []byte("DBBYTES")), types.MediaType(vulnDB.LayerMedia), types.OCIManifestSchema1, false, "tar root"},
		{"missing db file", "bad/nodb", singleFileTar(t, "metadata.json", []byte(stampTestMeta)), types.MediaType(vulnDB.LayerMedia), types.OCIManifestSchema1, false, "tar root"},
		{"wrong metadata version", "bad/version", dbFixtureTar(t, "trivy.db", `{"Version":7}`), types.MediaType(vulnDB.LayerMedia), types.OCIManifestSchema1, false, "metadata Version"},
		{"empty metadata (missing fields)", "bad/empty", dbFixtureTar(t, "trivy.db", `{}`), types.MediaType(vulnDB.LayerMedia), types.OCIManifestSchema1, false, "metadata Version"},
	}
	for _, c := range cases {
		a := vulnDB
		a.Repos = []string{host + "/" + c.repo}
		digest := pushDBImage(t, host, c.repo, c.tar, c.layerMT, c.manifestMT, c.extraLayer)
		_, _, err := fetchDB(context.Background(), a, digest, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.want, err)
		}
	}
}

// ResolveDB and fetchDB both fall back down the repo order: a broken first
// repo must not stop a healthy second one.
func TestRepoFallback(t *testing.T) {
	meta := `{"Version":2,"UpdatedAt":"2026-10-04T01:00:00Z"}`
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	a := vulnDB
	a.Repos = []string{"invalid.invalid/trivy-db", host + "/aquasec/trivy-db"}
	digest := pushDBImage(t, host, "aquasec/trivy-db", dbFixtureTar(t, "trivy.db", meta),
		types.MediaType(vulnDB.LayerMedia), types.OCIManifestSchema1, false)

	got, err := ResolveDB(context.Background(), a)
	if err != nil || got != digest {
		t.Fatalf("ResolveDB fallback = %q, %v; want %q", got, err, digest)
	}
	if _, _, err := fetchDB(context.Background(), a, got, t.TempDir()); err != nil {
		t.Fatalf("fetchDB fallback: %v", err)
	}
}

func TestDBStampJSONShape(t *testing.T) {
	st := DBStamp{Artifact: "vuln", Digest: "sha256:abc",
		UpdatedAt: time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC),
		SwappedAt: time.Date(2026, 10, 4, 2, 0, 0, 0, time.UTC)}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var back DBStamp
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != st {
		t.Fatalf("stamp round trip: %+v vs %+v", back, st)
	}
	if !strings.Contains(string(b), `"updatedAt"`) || !strings.Contains(string(b), `"swappedAt"`) {
		t.Fatalf("stamp json keys drifted: %s", b)
	}
}

// TestUpdateDBSwapLifecycle drives the full fetch-stage-swap-verify pipeline
// against a real container, with a fake artifact served from the loopback
// registry and a scratch CachePath: the swapped bytes are isolated from the
// host's real advisory data, but the container still mounts the real
// cavet-trivy-db named volume, which self-seeds from the dev image's baked
// cache on first mount. Docker-gated like the other integration tests.
func TestUpdateDBSwapLifecycle(t *testing.T) {
	c := New(devImage, "", t.TempDir(), "core")
	requireDaemon(t, c)
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = c.Remove(cctx)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	meta := `{"Version":2,"UpdatedAt":"2026-10-04T01:00:00Z"}`
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	a := vulnDB
	a.Repos = []string{host + "/aquasec/trivy-db"}
	a.CachePath = "/tmp/cavet-db-test" // scratch: swapped bytes stay out of the volume
	digest := pushDBImage(t, host, "aquasec/trivy-db", dbFixtureTar(t, "trivy.db", meta),
		types.MediaType(a.LayerMedia), types.OCIManifestSchema1, false)

	if err := c.EnsureRunning(ctx); err != nil {
		t.Fatalf("EnsureRunning: %v", err)
	}

	if _, err := c.ReadDBStamp(ctx, a); err != ErrNoStamp {
		t.Fatalf("unstamped cache must read ErrNoStamp, got %v", err)
	}

	sw, err := c.UpdateDB(ctx, a, digest)
	if err != nil {
		t.Fatalf("UpdateDB: %v", err)
	}
	if sw.Digest != digest || !sw.UpdatedAt.Equal(time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("swap record wrong: %+v", sw)
	}
	if b, err := c.CopyOut(ctx, a.CachePath+"/trivy.db"); err != nil || string(b) != "DBBYTES" {
		t.Fatalf("swapped db: %q %v", b, err)
	}
	stamp, err := c.ReadDBStamp(ctx, a)
	if err != nil || stamp.Digest != digest || stamp.Artifact != "vuln" {
		t.Fatalf("stamp after swap: %+v %v", stamp, err)
	}
	if !stamp.SwappedAt.Equal(sw.SwappedAt) {
		t.Fatalf("stamp swappedAt must match the swap record: %+v vs %+v", stamp, sw)
	}

	// A second swap over the live one must succeed (rm -rf clears db.next).
	if _, err := c.UpdateDB(ctx, a, digest); err != nil {
		t.Fatalf("re-swap: %v", err)
	}
}
