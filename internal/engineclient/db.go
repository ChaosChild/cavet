package engineclient

// Advisory database pipeline (W0 spike, 2026-10-04): cavet fetches the trivy
// DB OCI images host-side, verifies them, stages the two files into the
// artifact's named volume and swaps them live in one root exec. The engine
// container stays offline throughout and the engine image bytes never
// change; scans are unaffected (trivy runs --skip-db-update against whatever
// the volume holds).

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/moby/client"
)

// stampFile is cavet's per-volume swap record. It travels with the db files
// in the staged tar, so the swap leaves db, metadata and stamp consistent.
const stampFile = "cavet-db.json"

// Artifact describes one advisory database the engine consumes: where to
// fetch it (repos in fallback order, mirror first like trivy itself), the
// shape to insist on, and where it lives in the engine.
type Artifact struct {
	Name        string   // "vuln" | "java-db" (state/config key)
	Repos       []string // registry repos, fallback order
	Tag         string   // schema tag
	MetaVersion int      // metadata.json Version trivy expects exactly
	LayerMedia  string   // the one accepted layer media type
	DBFile      string   // trivy.db | trivy-java.db, at the layer root
	Volume      string   // one named volume per artifact (copy-on-first-mount)
	CachePath   string   // container path the volume binds at
}

// vulnDB/javaDB encode the W0 spike facts: flat single-layer images whose
// one gunzip yields trivy.db|trivy-java.db plus metadata.json at the tar
// root. There is no inner archive despite the layer title annotation.
var (
	vulnDB = Artifact{
		Name:        "vuln",
		Repos:       []string{"mirror.gcr.io/aquasec/trivy-db", "ghcr.io/aquasecurity/trivy-db"},
		Tag:         "2",
		MetaVersion: 2,
		LayerMedia:  "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
		DBFile:      "trivy.db",
		Volume:      "cavet-trivy-db",
		CachePath:   "/opt/trivy-cache/db",
	}
	javaDB = Artifact{
		Name:        "java-db",
		Repos:       []string{"mirror.gcr.io/aquasec/trivy-java-db", "ghcr.io/aquasecurity/trivy-java-db"},
		Tag:         "1",
		MetaVersion: 1,
		LayerMedia:  "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip",
		DBFile:      "trivy-java.db",
		Volume:      "cavet-trivy-java-db",
		CachePath:   "/opt/trivy-cache/java-db",
	}
)

// Artifacts returns the advisory databases for an engine variant in update
// order: the vuln DB always, the java DB only in full (the core image has no
// java-db).
func Artifacts(variant string) []Artifact {
	if variant == "full" {
		return []Artifact{vulnDB, javaDB}
	}
	return []Artifact{vulnDB}
}

// DBStamp is cavet-db.json inside an artifact volume: what is live and how
// it got there. Written by UpdateDB, read back by ReadDBStamp.
type DBStamp struct {
	Artifact  string    `json:"artifact"`
	Digest    string    `json:"digest"`
	UpdatedAt time.Time `json:"updatedAt"`
	SwappedAt time.Time `json:"swappedAt"`
}

// ErrNoStamp reports an artifact volume without cavet-db.json: update-db has
// never swapped there, so the volume holds the engine image's baked copy.
var ErrNoStamp = errors.New("advisory db not stamped")

// dbMetadata is the metadata.json subset trivy consults under
// --skip-db-update: it demands exactly the expected schema Version and
// refuses an empty db dir, which is why seeding must precede the first
// offline scan. DownloadedAt may be zero and is accepted (W0 spike).
type dbMetadata struct {
	Version      int       `json:"Version"`
	NextUpdate   time.Time `json:"NextUpdate"`
	UpdatedAt    time.Time `json:"UpdatedAt"`
	DownloadedAt time.Time `json:"DownloadedAt"`
}

// ResolveDB returns the manifest digest ("sha256:...") for a, trying the
// repos in fallback order. Anonymous auth by default: both registries serve
// these repos publicly.
func ResolveDB(ctx context.Context, a Artifact) (string, error) {
	var errs []string
	for _, repo := range a.Repos {
		ref, err := name.ParseReference(repo + ":" + a.Tag)
		if err != nil {
			errs = append(errs, repo+": "+err.Error())
			continue
		}
		d, err := remote.Head(ref, remote.WithContext(ctx))
		if err == nil {
			return d.Digest.String(), nil
		}
		errs = append(errs, repo+": "+err.Error())
	}
	return "", fmt.Errorf("resolve %s:%s: %s", a.Name, a.Tag, strings.Join(errs, "; "))
}

// Swap records one successful UpdateDB for the caller's bookkeeping.
type Swap struct {
	Digest    string    // resolved manifest digest (sha256:...)
	UpdatedAt time.Time // advisories date from metadata.json
	SwappedAt time.Time
	Bytes     int64 // compressed layer size
}

// UpdateDB runs the staged swap: fetch and verify into a host temp dir, copy
// the files into <CachePath>/db.next inside the volume, then one root exec
// renames trivy.db, then metadata.json, then the stamp into place and
// removes the staging dir. Renames stay inside the volume (cross-device
// rename fails EXDEV); db before metadata keeps trivy's consistency check
// sane mid-swap (W0 spike: verified clean under concurrent scans). Nothing
// is staged until fetch+verify pass; the swap is verified afterwards.
func (c *Client) UpdateDB(ctx context.Context, a Artifact, digest string) (Swap, error) {
	var sw Swap
	dir, err := os.MkdirTemp("", "cavet-db-")
	if err != nil {
		return sw, err
	}
	defer os.RemoveAll(dir)

	md, size, err := fetchDB(ctx, a, digest, dir)
	if err != nil {
		return sw, err
	}
	sw = Swap{Digest: digest, UpdatedAt: md.UpdatedAt, SwappedAt: time.Now().UTC(), Bytes: size}
	stamp, err := json.Marshal(DBStamp{
		Artifact: a.Name, Digest: digest,
		UpdatedAt: md.UpdatedAt, SwappedAt: sw.SwappedAt,
	})
	if err != nil {
		return sw, err
	}
	if err := os.WriteFile(filepath.Join(dir, stampFile), stamp, 0o644); err != nil {
		return sw, err
	}

	stage := a.CachePath + "/db.next"
	if res, err := c.ExecRoot(ctx, []string{"sh", "-c", "rm -rf " + stage + " && mkdir -p " + stage}); err != nil {
		return sw, fmt.Errorf("stage %s: %w", a.Name, err)
	} else if res.Code != 0 {
		return sw, fmt.Errorf("stage %s: code=%d stderr=%.200s", a.Name, res.Code, res.Stderr)
	}
	for _, name := range []string{a.DBFile, "metadata.json", stampFile} {
		if err := c.CopyToContainer(ctx, filepath.Join(dir, name), stage+"/"+name); err != nil {
			return sw, fmt.Errorf("stage %s: %w", a.Name, err)
		}
	}

	swap := "cd " + stage +
		" && mv " + a.DBFile + " .." +
		" && mv metadata.json .." +
		" && mv " + stampFile + " .." +
		" && cd .. && rm -rf db.next"
	res, err := c.ExecRoot(ctx, []string{"sh", "-c", swap})
	if err != nil {
		return sw, fmt.Errorf("swap %s: %w", a.Name, err)
	}
	if res.Code != 0 {
		return sw, fmt.Errorf("swap %s: code=%d stderr=%.200s", a.Name, res.Code, res.Stderr)
	}

	if err := c.verifySwap(ctx, a, md); err != nil {
		return sw, err
	}
	return sw, nil
}

// verifySwap re-reads the live metadata.json and demands the staged values:
// the swap's whole point is that --skip-db-update accepts exactly this
// version (W0 spike).
func (c *Client) verifySwap(ctx context.Context, a Artifact, md dbMetadata) error {
	b, err := c.CopyOut(ctx, a.CachePath+"/metadata.json")
	if err != nil {
		return fmt.Errorf("verify %s: %w", a.Name, err)
	}
	var live dbMetadata
	if err := json.Unmarshal(b, &live); err != nil {
		return fmt.Errorf("verify %s: metadata.json: %w", a.Name, err)
	}
	if live.Version != md.Version || !live.UpdatedAt.Equal(md.UpdatedAt) {
		return fmt.Errorf("verify %s: live metadata (Version %d, UpdatedAt %s) does not match staged (Version %d, UpdatedAt %s)",
			a.Name, live.Version, live.UpdatedAt.Format(time.RFC3339), md.Version, md.UpdatedAt.Format(time.RFC3339))
	}
	return nil
}

// ReadDBStamp returns the stamp from a's volume. A missing file maps to
// ErrNoStamp (the baked era); the caller renders it.
func (c *Client) ReadDBStamp(ctx context.Context, a Artifact) (DBStamp, error) {
	b, err := c.CopyOut(ctx, a.CachePath+"/"+stampFile)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return DBStamp{}, ErrNoStamp
		}
		return DBStamp{}, err
	}
	var st DBStamp
	if err := json.Unmarshal(b, &st); err != nil {
		return DBStamp{}, fmt.Errorf("stamp %s: %w", a.Name, err)
	}
	return st, nil
}

// DBInfo is the vuln DB's live identity for scan-time surfaces (PR B): what
// the scan's findings were matched against. Digest is empty in the baked era
// (the engine image's copy carries no manifest digest record); Source is
// "managed" after update-db, "baked" before.
type DBInfo struct {
	Digest    string
	UpdatedAt time.Time // advisories date (metadata.json)
	Source    string    // "managed" | "baked"
}

// ReadDBInfo reads the live vuln DB identity: the volume stamp when
// update-db has run there, else the baked metadata.json (CopyOut, like
// ReadDBStamp). Successful reads are cached on the client, so the scan path
// reads the container once per run whatever it feeds (findings join, header
// line); a failed read is not cached and surfaces to the caller.
func (c *Client) ReadDBInfo(ctx context.Context) (DBInfo, error) {
	if c.dbInfo != nil {
		return *c.dbInfo, nil
	}
	info, err := readDBInfo(ctx, vulnDB, c.CopyOut)
	if err != nil {
		return DBInfo{}, err
	}
	c.dbInfo = &info
	return info, nil
}

// readDBInfo is the stamp-or-baked decision over any CopyOut seam (the client
// in production, a fake in tests).
func readDBInfo(ctx context.Context, a Artifact, copyOut func(context.Context, string) ([]byte, error)) (DBInfo, error) {
	b, err := copyOut(ctx, a.CachePath+"/"+stampFile)
	if err == nil {
		var st DBStamp
		if err := json.Unmarshal(b, &st); err != nil {
			return DBInfo{}, fmt.Errorf("stamp %s: %w", a.Name, err)
		}
		return DBInfo{Digest: st.Digest, UpdatedAt: st.UpdatedAt, Source: "managed"}, nil
	}
	if !errdefs.IsNotFound(err) {
		return DBInfo{}, err
	}
	// No stamp: the baked era. metadata.json is the only record the engine
	// image's copy carries (no digest exists for it).
	mb, err := copyOut(ctx, a.CachePath+"/metadata.json")
	if err != nil {
		return DBInfo{}, fmt.Errorf("baked %s metadata: %w", a.Name, err)
	}
	var md dbMetadata
	if err := json.Unmarshal(mb, &md); err != nil {
		return DBInfo{}, fmt.Errorf("baked %s metadata.json: %w", a.Name, err)
	}
	return DBInfo{UpdatedAt: md.UpdatedAt, Source: "baked"}, nil
}

// fetchDB fetches a's image at digest and unpacks it into dir, trying the
// repos in fallback order (a digest names the same bytes everywhere, so the
// fallback only buys transport resilience). Returns the metadata and the
// compressed layer size.
func fetchDB(ctx context.Context, a Artifact, digest, dir string) (dbMetadata, int64, error) {
	var errs []string
	for _, repo := range a.Repos {
		md, size, err := fetchDBFrom(ctx, a, repo, digest, dir)
		if err == nil {
			return md, size, nil
		}
		errs = append(errs, repo+": "+err.Error())
	}
	return dbMetadata{}, 0, fmt.Errorf("fetch %s %s: %s", a.Name, digest, strings.Join(errs, "; "))
}

func fetchDBFrom(ctx context.Context, a Artifact, repo, digest, dir string) (dbMetadata, int64, error) {
	var md dbMetadata
	ref, err := name.NewDigest(repo + "@" + digest)
	if err != nil {
		return md, 0, err
	}
	got, err := remote.Get(ref, remote.WithContext(ctx))
	if err != nil {
		return md, 0, err
	}
	// Reject index manifests outright: Image() would silently resolve a
	// platform child and diverge from the resolved digest.
	if mt := got.MediaType; mt != types.OCIManifestSchema1 && mt != types.DockerManifestSchema2 {
		return md, 0, fmt.Errorf("manifest media type %q, want an image manifest", mt)
	}
	img, err := got.Image()
	if err != nil {
		return md, 0, err
	}
	layers, err := img.Layers()
	if err != nil {
		return md, 0, err
	}
	if len(layers) != 1 {
		return md, 0, fmt.Errorf("%d layers, want exactly one", len(layers))
	}
	mt, err := layers[0].MediaType()
	if err != nil {
		return md, 0, err
	}
	if mt != types.MediaType(a.LayerMedia) {
		return md, 0, fmt.Errorf("layer media type %q, want %q", mt, a.LayerMedia)
	}
	size, err := layers[0].Size()
	if err != nil {
		return md, 0, err
	}
	rc, err := layers[0].Compressed() // library verifies the blob sha256 while streaming
	if err != nil {
		return md, 0, err
	}
	defer rc.Close()
	md, err = extractDBLayer(rc, a, dir)
	return md, size, err
}

// extractDBLayer unwraps the layer stream: one gunzip yields a tar whose
// trivy.db|trivy-java.db and metadata.json sit at the root (W0 spike: no
// inner archive). Unknown entries are ignored; the two required files and a
// Version match are mandatory.
func extractDBLayer(rc io.Reader, a Artifact, dir string) (dbMetadata, error) {
	var md dbMetadata
	gz, err := gzip.NewReader(rc)
	if err != nil {
		return md, fmt.Errorf("%s layer: %w", a.Name, err)
	}
	tr := tar.NewReader(gz)
	var gotDB, gotMeta bool
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return md, fmt.Errorf("%s layer tar: %w", a.Name, err)
		}
		switch strings.TrimPrefix(hdr.Name, "./") {
		case a.DBFile:
			if err := writeFile(filepath.Join(dir, a.DBFile), tr); err != nil {
				return md, fmt.Errorf("%s: %w", a.Name, err)
			}
			gotDB = true
		case "metadata.json":
			var b bytes.Buffer
			if _, err := io.Copy(&b, tr); err != nil {
				return md, fmt.Errorf("%s metadata: %w", a.Name, err)
			}
			if err := json.Unmarshal(b.Bytes(), &md); err != nil {
				return md, fmt.Errorf("%s metadata.json: %w", a.Name, err)
			}
			if err := writeFile(filepath.Join(dir, "metadata.json"), &b); err != nil {
				return md, fmt.Errorf("%s: %w", a.Name, err)
			}
			gotMeta = true
		}
	}
	if !gotDB || !gotMeta {
		return md, fmt.Errorf("%s layer: %s and metadata.json must sit at the tar root", a.Name, a.DBFile)
	}
	if md.Version != a.MetaVersion {
		return md, fmt.Errorf("%s metadata Version %d, want %d", a.Name, md.Version, a.MetaVersion)
	}
	return md, nil
}

// writeFile streams r into a new dst file.
func writeFile(dst string, r io.Reader) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// VolumeExists reports whether a named volume exists on the host. update-db
// uses it as the java-db trigger: a host that never ran a full-variant
// container has no java-db volume and never fetches the java DB.
func (c *Client) VolumeExists(ctx context.Context, volume string) (bool, error) {
	if err := c.connect(); err != nil {
		return false, err
	}
	_, err := c.docker.VolumeInspect(ctx, volume, client.VolumeInspectOptions{})
	if errdefs.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}
