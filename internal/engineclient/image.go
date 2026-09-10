package engineclient

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
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

// tailLimit is the output tail kept for the error path (house style): the
// failure reason lives at the end of a build log.
const tailLimit = 300

// BuildImage builds tag from the dockerfile at dockerfilePath (absolute or
// contextDir-relative) with contextDir as the build context by execing
// `docker buildx build --load`. The daemon API's /build endpoint with BuildKit
// wedges indefinitely on large builds on Docker Desktop for Windows (verified
// by a standalone probe with zero cavet code; the CLI path completes the same
// build, ~9 minutes cold cache), so the CLI is the one deliberate exception to
// this package's SDK-only daemon access. target names a build stage for
// multi-stage Dockerfiles; empty means the Dockerfile default (the last
// stage). output receives the child's combined stdout/stderr live (nil means
// discard); buildx runs with --progress=plain so that stream is parseable and
// timestamped. The context is sent by buildx per standard Docker semantics:
// .dockerignore is the exclusion mechanism. On failure the error carries only
// the tail of the output.
func (c *Client) BuildImage(ctx context.Context, dockerfilePath, contextDir, tag, target string, output io.Writer) error {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("image build %s: the docker CLI was not found; Docker (with the buildx plugin, bundled with Docker Desktop) is required to build scan images: %w", tag, err)
	}
	absContext, err := filepath.Abs(contextDir)
	if err != nil {
		return fmt.Errorf("image build %s: %w", tag, err)
	}
	absDockerfile, err := filepath.Abs(dockerfilePath)
	if err != nil {
		return fmt.Errorf("image build %s: %w", tag, err)
	}
	cmd := exec.CommandContext(ctx, docker, buildxArgs(absDockerfile, absContext, tag, target)...)
	var tail tailWriter
	var w io.Writer = &tail
	if output != nil {
		w = io.MultiWriter(output, &tail)
	}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Run(); err != nil {
		if out := tail.String(); out != "" {
			return fmt.Errorf("image build %s: %w; output: %s", tag, err, out)
		}
		return fmt.Errorf("image build %s: %w", tag, err)
	}
	return nil
}

// buildxArgs assembles the `docker buildx build` argument vector; absolute
// paths for both the dockerfile and the context, plain progress for a
// parseable stream.
func buildxArgs(dockerfilePath, contextDir, tag, target string) []string {
	args := []string{"buildx", "build", "--load", "--progress=plain", "-t", tag, "-f", dockerfilePath}
	if target != "" {
		args = append(args, "--target", target)
	}
	return append(args, contextDir)
}

// tailWriter keeps the last tailLimit bytes written to it, so the failure
// reason at the end of an unbounded build stream survives without buffering
// the whole stream.
type tailWriter struct {
	buf [tailLimit]byte
	n   int // bytes buffered
}

func (t *tailWriter) Write(p []byte) (int, error) {
	if len(p) >= tailLimit {
		copy(t.buf[:], p[len(p)-tailLimit:])
		t.n = tailLimit
		return len(p), nil
	}
	keep := tailLimit - len(p)
	if t.n > keep {
		copy(t.buf[:], t.buf[t.n-keep:t.n]) // shift the kept tail left
		t.n = keep
	}
	copy(t.buf[t.n:], p)
	t.n += len(p)
	return len(p), nil
}

func (t *tailWriter) String() string { return string(t.buf[:t.n]) }

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
