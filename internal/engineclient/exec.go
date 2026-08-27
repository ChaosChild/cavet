package engineclient

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/moby/moby/client"
)

// ExecResult carries a container command's captured streams and exit code.
type ExecResult struct {
	Stdout []byte
	Stderr []byte
	Code   int
}

// Exec runs cmd in the container with stdout/stderr demultiplexed. Workdir is
// /workspace. Exit codes are data (gitleaks exits 1 on leaks — cli-spec §7);
// transport errors are the only error returns.
func (c *Client) Exec(ctx context.Context, cmd []string) (ExecResult, error) {
	id, err := c.docker.ExecCreate(ctx, c.name, client.ExecCreateOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   "/workspace",
	})
	if err != nil {
		return ExecResult{}, fmt.Errorf("exec create %v: %w", cmd, err)
	}
	attach, err := c.docker.ExecAttach(ctx, id.ID, client.ExecAttachOptions{})
	if err != nil {
		return ExecResult{}, fmt.Errorf("exec attach: %w", err)
	}
	defer attach.Close()
	var stdout, stderr bytes.Buffer
	if err := demux(attach.Reader, &stdout, &stderr); err != nil {
		return ExecResult{}, fmt.Errorf("exec stream: %w", err)
	}
	for {
		insp, err := c.docker.ExecInspect(ctx, id.ID, client.ExecInspectOptions{})
		if err != nil {
			return ExecResult{}, fmt.Errorf("exec inspect: %w", err)
		}
		if !insp.Running {
			return ExecResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Code: insp.ExitCode}, nil
		}
		select {
		case <-ctx.Done():
			return ExecResult{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// demux splits Docker's attach multiplexing: every chunk is an 8-byte header
// (stream byte — 1 stdout, 2 stderr — three zeros, payload length big-endian)
// followed by the payload. TTY mode would disable framing; we never set it.
// ponytail: hand-rolled — the stdcopy package left the split-out client module.
func demux(r io.Reader, stdout, stderr io.Writer) error {
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		dst := io.Discard
		switch hdr[0] {
		case 1:
			dst = stdout
		case 2:
			dst = stderr
		}
		if _, err := io.CopyN(dst, r, int64(binary.BigEndian.Uint32(hdr[4:8]))); err != nil {
			return err
		}
	}
}

// CopyOut retrieves a single file's bytes from the container. Reports are
// megabytes at worst (spike §5); read into memory and discard (cli-spec §10.3).
func (c *Client) CopyOut(ctx context.Context, containerPath string) ([]byte, error) {
	res, err := c.docker.CopyFromContainer(ctx, c.name, client.CopyFromContainerOptions{SourcePath: containerPath})
	if err != nil {
		return nil, fmt.Errorf("copy out %s: %w", containerPath, err)
	}
	defer res.Content.Close()
	tr := tar.NewReader(res.Content)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("no regular file at %s", containerPath)
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(tr)
		}
	}
}

// NextScanDir allocates a fresh staging directory inside the container so
// concurrent-ish scans never share a temp dir; dirs die with the container
// (cli-spec §6 staged mechanics).
func (c *Client) NextScanDir() string {
	c.scans++
	return fmt.Sprintf("/scan/%d", c.scans)
}
