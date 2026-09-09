package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ChaosChild/cavet/internal/store"
)

// scanImages runs the image phase: build each configured Dockerfile host-side
// (tag cavet-scan-<n>), save the image tar to .cavet/tmp, copy it into the
// engine at /scan, and trivy it offline. The per-image SARIF runs come back
// stitched into one trivy-image report. Any failure aborts the scan loudly,
// never a silent skip.
func scanImages(ctx context.Context, s *store.Store, r Runner, dockerfiles []string) ([]byte, error) {
	// CopyToContainer needs the destination directory to exist; a pure image
	// scan never created a scan dir yet.
	if res, err := r.Exec(ctx, []string{"mkdir", "-p", "/scan"}); err != nil || res.Code != 0 {
		return nil, fmt.Errorf("preparing /scan in the engine: %v %.200s", err, res.Stderr)
	}
	docs := make([][]byte, 0, len(dockerfiles))
	for n, df := range dockerfiles {
		b, err := scanOneImage(ctx, s, r, n, df)
		if err != nil {
			return nil, err
		}
		docs = append(docs, b)
	}
	return stitchRuns(docs)
}

// scanOneImage builds and scans one Dockerfile. The tar and the built image
// are transient: both are removed on the way out, best-effort on error.
func scanOneImage(ctx context.Context, s *store.Store, r Runner, n int, dockerfile string) ([]byte, error) {
	host := filepath.Join(s.Root, filepath.FromSlash(dockerfile))
	if fi, err := os.Stat(host); err != nil || fi.IsDir() {
		return nil, fmt.Errorf("dockerfile %s not found in the repository; "+
			"run 'cavet image remove %s' or restore the file", dockerfile, dockerfile)
	}
	tag := fmt.Sprintf("cavet-scan-%d", n)
	// Context is the Dockerfile's directory, the docker build -f convention;
	// root Dockerfiles get the repository root, the usual case.
	// ponytail: Dockerfiles that expect a different context (a repo-root
	// context with COPY subdir/...) will fail to build; the ceiling is a
	// per-entry context in the container_images list form.
	if err := r.BuildImage(ctx, host, filepath.Dir(host), tag); err != nil {
		return nil, fmt.Errorf("image build for %s failed: %w", dockerfile, err)
	}
	tarPath := filepath.Join(s.Cavet, "tmp", fmt.Sprintf("image-%d.tar", n))
	defer func() {
		// A fresh context: this scan's ctx may already be cancelled.
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		_ = os.Remove(tarPath)
		_ = r.RemoveImage(cctx, tag)
	}()
	if err := r.SaveImage(ctx, tag, tarPath); err != nil {
		return nil, fmt.Errorf("saving built image %s: %w", tag, err)
	}
	in := fmt.Sprintf("/scan/image-%d.tar", n)
	if err := r.CopyToContainer(ctx, tarPath, in); err != nil {
		return nil, fmt.Errorf("copying %s into the engine: %w", filepath.ToSlash(tarPath), err)
	}
	raw, err := runScanners(ctx, r, []string{"trivy-image"}, in)
	if err != nil {
		return nil, err
	}
	return raw["trivy-image"], nil
}
