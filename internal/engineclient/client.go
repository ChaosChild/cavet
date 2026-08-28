// Package engineclient owns the long-lived cavet-engine container for one
// repository: lifecycle, exec plumbing, report copy-out, and path translation
// (cli-spec §10). It knows Docker and paths; it never parses findings.
package engineclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// probeTiming: cold start (image unpack + cache checks) can take seconds;
// 30 s ceiling per spec (cli-spec §10.2).
const (
	probeTimeout = 30 * time.Second
	probeEvery   = 500 * time.Millisecond
)

type Client struct {
	docker *client.Client
	image  string // image ref to run
	digest string // pinned digest ("" = dev mode, no drift gate)
	root   string // absolute host repository root
	name   string // cavet-<12 hex of sha256(root)> (cli-spec §10.1)

	scans int // scan-dir tiebreaker (see NextScanDir)
}

// ContainerName derives the stable per-repository container name.
func ContainerName(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	sum := sha256.Sum256([]byte(strings.ToLower(abs)))
	return "cavet-" + hex.EncodeToString(sum[:])[:12]
}

// New builds a client. pinnedDigest may be empty in development (local image
// tag, no drift enforcement); production always pins (spec §3.4).
func New(image, pinnedDigest, root string) *Client {
	return &Client{
		image:  image,
		digest: pinnedDigest,
		root:   root,
		name:   ContainerName(root),
	}
}

func (c *Client) Name() string { return c.name }

func (c *Client) connect() error {
	if c.docker != nil {
		return nil
	}
	d, err := client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	c.docker = d
	return nil
}

// Ping reports whether a Docker daemon is reachable.
func (c *Client) Ping(ctx context.Context) error {
	if err := c.connect(); err != nil {
		return err
	}
	_, err := c.docker.Ping(ctx, client.PingOptions{})
	return err
}

// ImagePresent reports whether the engine image exists locally.
func (c *Client) ImagePresent(ctx context.Context) error {
	if err := c.connect(); err != nil {
		return err
	}
	_, err := c.docker.ImageInspect(ctx, c.image)
	return err
}

// EnsureRunning guarantees a healthy container: create if absent, restart if
// stopped (transparently, spec §7.1), verify the digest first. Digest drift is
// a hard stop, never silent scanning on a stale engine (cli-spec §10.2).
func (c *Client) EnsureRunning(ctx context.Context) error {
	if err := c.connect(); err != nil {
		return err
	}
	res, err := c.docker.ContainerInspect(ctx, c.name, client.ContainerInspectOptions{})
	if err != nil {
		if errdefs.IsNotFound(err) {
			return c.createAndProbe(ctx)
		}
		return err
	}
	if err := c.checkDigest(ctx, res.Container.Image); err != nil {
		return err
	}
	if res.Container.State != nil && res.Container.State.Running {
		return nil
	}
	if _, err := c.docker.ContainerStart(ctx, c.name, client.ContainerStartOptions{}); err != nil {
		return err
	}
	return c.probe(ctx)
}

func (c *Client) createAndProbe(ctx context.Context) error {
	cfg := &container.Config{
		Image: c.image,
		Cmd:   []string{"sleep", "infinity"}, // entrypoint prepares git + dirs, then parks
	}
	if runtime.GOOS == "linux" {
		cfg.User = strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	}
	host := &container.HostConfig{
		Binds:       []string{strings.ReplaceAll(c.root, "\\", "/") + ":/workspace"},
		NetworkMode: "none", // offline by construction; no scanner tier needs it (spec §7.5)
	}
	if _, err := c.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: cfg, HostConfig: host, Name: c.name,
	}); err != nil {
		return fmt.Errorf("create engine container: %w", err)
	}
	if _, err := c.docker.ContainerStart(ctx, c.name, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start engine container: %w", err)
	}
	return c.probe(ctx)
}

// checkDigest enforces the pinned digest when one is configured.
func (c *Client) checkDigest(ctx context.Context, runningID string) error {
	if c.digest == "" {
		return nil // development: local tag, no pin
	}
	ref := c.image
	if !strings.Contains(c.image, "@") {
		ref = c.image + "@" + c.digest
	}
	insp, err := c.docker.ImageInspect(ctx, ref)
	if err != nil {
		return fmt.Errorf("engine image %s not present locally; run 'cavet engine pull': %w", ref, err)
	}
	if insp.ID != runningID {
		return fmt.Errorf("engine digest drift: container runs %s, config pins %s; run 'cavet rebaseline'", runningID, c.digest)
	}
	return nil
}

// probe waits for cavet-healthcheck to pass (cli-spec §10.2).
func (c *Client) probe(ctx context.Context) error {
	deadline := time.Now().Add(probeTimeout)
	for {
		res, err := c.Exec(ctx, []string{"cavet-healthcheck"})
		if err == nil && res.Code == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("engine container failed health probe within %s: code=%d err=%v stderr=%.200s",
				probeTimeout, res.Code, err, res.Stderr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(probeEvery):
		}
	}
}

// Remove force-removes the container; the container holds no unique state
// (cli-spec §5 engine stop).
func (c *Client) Remove(ctx context.Context) error {
	if err := c.connect(); err != nil {
		return err
	}
	_, err := c.docker.ContainerRemove(ctx, c.name, client.ContainerRemoveOptions{Force: true})
	return err
}

// Pull streams the image from its registry. Progress reporting is the
// caller's job; drain the reader to completion or the pull aborts.
func (c *Client) Pull(ctx context.Context, ref string) (io.ReadCloser, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}
	return c.docker.ImagePull(ctx, ref, client.ImagePullOptions{})
}

// ImageDigest returns the image's registry digest when it has one
// (locally built images have none) — the pin `cavet init` records.
func (c *Client) ImageDigest(ctx context.Context, ref string) (string, error) {
	if err := c.connect(); err != nil {
		return "", err
	}
	insp, err := c.docker.ImageInspect(ctx, ref)
	if err != nil {
		return "", err
	}
	for _, rd := range insp.RepoDigests {
		if i := strings.Index(rd, "@sha256:"); i >= 0 {
			return rd[i+1:], nil
		}
	}
	return "", nil // local-only image: nothing recordable
}

// Status reports container state without side effects. healthy means the
// healthcheck currently passes (warm).
func (c *Client) Status(ctx context.Context) (running, healthy bool, imageID string, err error) {
	if err = c.connect(); err != nil {
		return
	}
	res, ierr := c.docker.ContainerInspect(ctx, c.name, client.ContainerInspectOptions{})
	if ierr != nil {
		if errdefs.IsNotFound(ierr) {
			return false, false, "", nil
		}
		return false, false, "", ierr
	}
	running = res.Container.State != nil && res.Container.State.Running
	imageID = res.Container.Image
	if running {
		r, _ := c.Exec(ctx, []string{"cavet-healthcheck"})
		healthy = r.Code == 0
	}
	return running, healthy, imageID, nil
}
