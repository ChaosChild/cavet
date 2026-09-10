package scan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ChaosChild/cavet/internal/config"
	"github.com/ChaosChild/cavet/internal/projection"
	"github.com/ChaosChild/cavet/internal/store"
)

// scanImages runs the image phase: build each configured Dockerfile host-side
// (transient tag cavet-scan-<repo-hash>-<n>-<rand>), save the image tar to
// .cavet/tmp, copy it into the engine at /scan, and trivy it offline. The
// per-image SARIF
// runs come back stitched into one trivy-image report plus pre-parsed findings
// (located at each Dockerfile, identity-bound to the Dockerfile path for the
// img: fingerprint namespace). Any failure aborts the scan loudly, never a
// silent skip.
func scanImages(ctx context.Context, s *store.Store, r Runner, images []config.ImageEntry, staged bool) ([]byte, []projection.Finding, error) {
	// CopyToContainer needs the destination directory to exist; a pure image
	// scan never created a scan dir yet.
	if res, err := r.Exec(ctx, []string{"mkdir", "-p", "/scan"}); err != nil || res.Code != 0 {
		return nil, nil, fmt.Errorf("preparing /scan in the engine: %v %.200s", err, res.Stderr)
	}
	docs := make([][]byte, 0, len(images))
	var findings []projection.Finding
	for n, img := range images {
		b, fs, err := scanOneImage(ctx, s, r, n, img, staged)
		if err != nil {
			return nil, nil, err
		}
		docs = append(docs, b)
		findings = append(findings, fs...)
	}
	stitched, err := stitchRuns(docs)
	if err != nil {
		return nil, nil, err
	}
	return stitched, findings, nil
}

// scanOneImage builds and scans one Dockerfile, returning its SARIF and its
// parsed findings (located at the Dockerfile, identity-bound to the
// Dockerfile path). The tar and the built image are transient: both are
// removed on the way out, best-effort on error.
func scanOneImage(ctx context.Context, s *store.Store, r Runner, n int, img config.ImageEntry, staged bool) ([]byte, []projection.Finding, error) {
	dockerfile := img.Dockerfile
	host := filepath.Join(s.Root, filepath.FromSlash(dockerfile))
	if fi, err := os.Stat(host); err != nil || fi.IsDir() {
		return nil, nil, fmt.Errorf("dockerfile %s not found in the repository; "+
			"run 'cavet image remove %s' or restore the file", dockerfile, dockerfile)
	}
	// Salted with a hash of the repository root plus a per-scan random
	// suffix: two cavet processes in different repositories share one daemon,
	// and two overlapping scans in the SAME repository (a long scan plus a
	// pre-commit hook) share the root hash, so colliding tags would let one
	// overwrite the other's image between build and save.
	salt := fmt.Sprintf("%x", sha256.Sum256([]byte(s.Root)))[:12]
	var rnd [2]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, nil, fmt.Errorf("salting the transient image tag: %w", err)
	}
	tag := fmt.Sprintf("cavet-scan-%s-%d-%x", salt, n, rnd) // transient build/remove tag, never identity
	// The img: fingerprint's imageName is the configured Dockerfile path,
	// slash-normalised: identity must survive rebuilds and reordering of the
	// container_images list (design D3): the ordinal tag would re-identify
	// every image finding and orphan triage state.
	identity := filepath.ToSlash(dockerfile)
	// Context is the Dockerfile's directory, the docker build -f convention;
	// root Dockerfiles get the repository root, the usual case.
	// ponytail: Dockerfiles that expect a different context (a repo-root
	// context with COPY subdir/...) will fail to build; the ceiling is a
	// per-entry context in the container_images list form.
	if staged {
		// Divergence semantics: this scan's coverage credits the INDEX (the
		// staged checkout describes what will be committed) while the build
		// below compiles WORKING-TREE content, because the host-side build
		// reads the file on disk. With partial staging that mismatch can
		// wrongly remediate or miss detection, so it warns loudly and
		// proceeds; see stagedDiverges.
			if div, err := stagedDiverges(ctx, r, dockerfile); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s index/worktree comparison failed: %v\n", dockerfile, err)
		} else if div {
			fmt.Fprintf(os.Stderr, "warning: staged %s differs from the working tree; "+
				"the image build uses WORKING-TREE content while this scan's coverage describes INDEX content\n", dockerfile)
		}
	}
	if err := r.BuildImage(ctx, host, filepath.Dir(host), tag, img.Target, os.Stderr); err != nil {
		return nil, nil, fmt.Errorf("image build for %s failed: %w", dockerfile, err)
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
		return nil, nil, fmt.Errorf("saving built image %s: %w", tag, err)
	}
	in := fmt.Sprintf("/scan/image-%d.tar", n)
	if err := r.CopyToContainer(ctx, tarPath, in); err != nil {
		return nil, nil, fmt.Errorf("copying %s into the engine: %w", filepath.ToSlash(tarPath), err)
	}
	raw, err := runScanners(ctx, r, []string{"trivy-image"}, in)
	if err != nil {
		return nil, nil, err
	}
	report := raw["trivy-image"]
	// Parsing happens here, not in parseAndMerge: the per-image report needs
	// its own Dockerfile as the location target, and the img: fingerprint
	// namespace binds to the configured image, not the transient build tag.
	fs, warns, err := projection.Parse("trivy-image", report, dockerfile)
	if err != nil {
		return nil, nil, err
	}
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	for i := range fs {
		fs[i].ImageName = identity
	}
	return report, fs, nil
}

// stagedDiverges reports whether the index's copy of path differs from the
// working-tree file, per git diff-files --quiet (exit status 1 = diverges,
// 0 = identical). The comparison is git's own filter-aware one, so checkout
// filters like core.autocrlf do not read a smudged (CRLF) working tree as
// divergent the way a raw blob-vs-file hash would. Divergence semantics: the
// staged image phase builds WORKING-TREE content while staged coverage
// credits the INDEX, so with partial staging (the fix in the tree, the CVE
// in the index) the scan can wrongly remediate or miss detection; the caller
// warns and proceeds, since refusing would hide the tree's state too.
func stagedDiverges(ctx context.Context, r Runner, path string) (bool, error) {
	res, err := r.Exec(ctx, []string{"git", "diff-files", "--quiet", "--", path})
	if err != nil {
		return false, err
	}
	switch res.Code {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("git diff-files --quiet -- %s: %.200s", path, res.Stderr)
	}
}
