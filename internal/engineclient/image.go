package engineclient

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

// toContainerPath normalizes a path bound for the Docker API the way binds()
// does: the daemon is POSIX-side, so backslash separators from a Windows host
// become forward slashes regardless of the client's own OS (the SDK's helpers
// are filepath-based and therefore host-dependent).
func toContainerPath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// CopyToContainer copies one host file (srcPath) into the engine container at
// dstPath (an absolute container path such as /scan/image-0.tar), mirroring
// CopyOut. The container-side parent directory must already exist: the daemon
// extracts a tar into the destination's directory, so the file travels as a
// tar entry named after dstPath's base (docker cp wire convention).
func (c *Client) CopyToContainer(ctx context.Context, srcPath, dstPath string) error {
	if err := c.connect(); err != nil {
		return err
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("copy in %s: %w", dstPath, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("copy in %s: %w", dstPath, err)
	}
	dst := toContainerPath(dstPath)
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		hdr := &tar.Header{ // path, not filepath: dst is a container path
			Name:     path.Base(dst),
			Mode:     int64(st.Mode().Perm()),
			Size:     st.Size(),
			ModTime:  st.ModTime(),
			Typeflag: tar.TypeReg,
		}
		werr := tw.WriteHeader(hdr)
		if werr == nil {
			_, werr = io.Copy(tw, f)
		}
		if werr == nil {
			werr = tw.Close()
		}
		_ = pw.CloseWithError(werr) // a short body aborts the daemon's extract
	}()
	if _, err := c.docker.CopyToContainer(ctx, c.name, client.CopyToContainerOptions{
		DestinationPath: path.Dir(dst),
		Content:         pr,
	}); err != nil {
		return fmt.Errorf("copy in %s: %w", dstPath, err)
	}
	return nil
}

// BuildImage builds tag from the dockerfile at dockerfilePath (absolute or
// contextDir-relative) with contextDir streamed as the build context. Build
// failures surface the daemon's error plus a truncated build log; the
// response body is the only place the daemon reports them.
func (c *Client) BuildImage(ctx context.Context, dockerfilePath, contextDir, tag string) error {
	if err := c.connect(); err != nil {
		return err
	}
	dockerfile, err := buildDockerfileRef(dockerfilePath, contextDir)
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() {
		_ = pw.CloseWithError(tarDir(contextDir, pw))
	}()
	res, err := c.docker.ImageBuild(ctx, pr, client.ImageBuildOptions{
		Dockerfile: dockerfile,
		Tags:       []string{tag},
	})
	if err != nil {
		return fmt.Errorf("image build %s: %w", tag, err)
	}
	defer res.Body.Close()
	if err := buildFailure(res.Body); err != nil {
		return fmt.Errorf("image build %s: %w", tag, err)
	}
	return nil
}

// buildDockerfileRef reduces dockerfilePath to a contextDir-relative POSIX
// path for the Dockerfile option: the daemon locates the dockerfile inside
// the context tar, not on the host.
func buildDockerfileRef(dockerfilePath, contextDir string) (string, error) {
	base, err := filepath.Abs(contextDir)
	if err != nil {
		return "", fmt.Errorf("build context: %w", err)
	}
	p := dockerfilePath
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("dockerfile %s outside build context %s", dockerfilePath, contextDir)
	}
	return toContainerPath(rel), nil
}

// buildFailure scans the build log's NDJSON stream for an error event. The
// daemon reports build failures in a 200 response body, so reading it is the
// only way to see them; the log tail is truncated per house style (~300 chars).
func buildFailure(r io.Reader) error {
	var log strings.Builder
	var failure string
	dec := json.NewDecoder(r)
	for {
		var ev struct {
			Stream string `json:"stream"`
			Error  string `json:"error"`
		}
		if err := dec.Decode(&ev); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("build log: %w", err)
		}
		log.WriteString(ev.Stream)
		if ev.Error != "" {
			failure = ev.Error
		}
	}
	if failure != "" {
		return fmt.Errorf("%s; output: %.300s", failure, log.String())
	}
	return nil
}

// SaveImage streams ref from the daemon to destPath as a tar, creating parent
// directories (mirrors how report paths are laid out).
func (c *Client) SaveImage(ctx context.Context, ref, destPath string) error {
	if err := c.connect(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("save image %s: %w", ref, err)
	}
	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("save image %s: %w", ref, err)
	}
	rc, err := c.docker.ImageSave(ctx, []string{ref})
	if err != nil {
		f.Close()
		return fmt.Errorf("save image %s: %w", ref, err)
	}
	defer rc.Close()
	if _, err := io.Copy(f, rc); err != nil {
		f.Close()
		return fmt.Errorf("save image %s: %w", ref, err)
	}
	return f.Close()
}

// RemoveImage force-removes ref; a missing image is not an error so scan
// teardown stays idempotent.
func (c *Client) RemoveImage(ctx context.Context, ref string) error {
	if err := c.connect(); err != nil {
		return err
	}
	_, err := c.docker.ImageRemove(ctx, ref, client.ImageRemoveOptions{Force: true})
	if errdefs.IsNotFound(err) {
		return nil
	}
	return err
}

// tarDir writes dir's contents as an uncompressed tar with dir-relative POSIX
// entry names, streaming so arbitrarily large build contexts never buffer.
// ponytail: no .dockerignore and non-regular files (symlinks, fifos) are
// skipped silently; scan-target images copy real files, and the upgrade path
// is .dockerignore parsing plus symlink handling in the walk.
func tarDir(dir string, w io.Writer) error {
	tw := tar.NewWriter(w)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil // the context root is implicit
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.IsDir(), info.Mode().IsRegular():
		default:
			return nil // see ponytail note above
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/" // extractor convention: directories end in /
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return err
	}
	return tw.Close()
}
