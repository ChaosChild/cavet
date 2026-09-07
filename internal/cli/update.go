package cli

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// updateRepo mirrors the installers (installers/binary.sh, binary.ps1): the
// tag comes from the GitHub API, assets from the release download base, and
// verification is checksums.txt plus the keyless Sigstore bundle.
const updateRepo = "ChaosChild/cavet"

// The installers' cosign identity pin, copied verbatim: only the repo's own
// release workflow may have signed. Change both together.
const (
	updateIdentityRegexp = `^https://github\.com/ChaosChild/cavet/\.github/workflows/release\.yml@`
	updateOIDCIssuer     = "https://token.actions.githubusercontent.com"
)

// Resource caps. A release archive is a few MiB; anything bigger is
// hostility, not an update. Entry bounds keep crafted archives from burning
// time on thousands of junk headers.
var (
	updateMaxAsset   int64 = 512 << 20 // archive download and binary entry
	updateMaxText    int64 = 1 << 20   // checksums.txt, sigstore bundle, API body
	updateMaxEntries       = 4096
)

// updateAPI/updateDL/updateHTTPClient are vars so tests can point the client
// at httptest servers; the explicit timeout replaces the default client's
// none.
var (
	updateAPI        = "https://api.github.com/repos/" + updateRepo + "/releases/latest"
	updateDL         = "https://github.com/" + updateRepo + "/releases/download"
	updateHTTPClient = &http.Client{Timeout: 60 * time.Second}
	// updateRename is os.Rename except in tests, which force the windows
	// rollback path by failing a chosen call.
	updateRename = os.Rename
)

func newUpdateCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the cavet binary in place from GitHub releases",
		Long: "Download the latest GitHub release, verify it against checksums.txt " +
			"and its Sigstore bundle (cosign required for the signature), and swap " +
			"the running binary at its real install location. --check only reports. " +
			"Development and unversioned builds refuse: reinstall with the " +
			"installers or go install instead.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runUpdate(check)
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "report whether an update exists; no download, no replace")
	return cmd
}

// runUpdate mirrors installers/binary.{sh,ps1}: resolve latest, compare,
// download, checksum, signature, extract the one binary, swap it in. The
// installed binary is never touched unless download, verification and
// extraction all succeeded.
func runUpdate(check bool) error {
	cur := strings.TrimPrefix(resolveVersion(), "v")
	from, ok := parseVersion(cur)
	if !ok {
		return fail(cur + " is a development or unversioned build: update it with the installers or 'go install github.com/ChaosChild/cavet/cmd/cavet@latest' instead")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	latest, err := latestRelease(ctx, cur)
	if err != nil {
		return fail(err.Error())
	}
	next := strings.TrimPrefix(latest, "v")
	to, ok := parseVersion(next)
	if !ok {
		return fail("github named a non-semver latest release: " + latest)
	}
	if compareVersion(to, from) <= 0 {
		fmt.Printf("cavet is up to date (%s)\n", cur)
		return nil
	}
	fmt.Printf("update available: %s -> %s\n", cur, next)
	if check {
		return nil
	}
	archive, ok := assetName(runtime.GOOS, runtime.GOARCH, next)
	if !ok {
		return fail("unsupported platform " + runtime.GOOS + "/" + runtime.GOARCH +
			" (supported: windows/amd64, windows/arm64, darwin/amd64, darwin/arm64, linux/amd64, linux/arm64)")
	}
	tmp, err := os.MkdirTemp("", "cavet-update-")
	if err != nil {
		return fail(err.Error())
	}
	defer os.RemoveAll(tmp)

	checksums := filepath.Join(tmp, "checksums.txt")
	if err := download(ctx, cur, updateDL+"/v"+next+"/checksums.txt", checksums, updateMaxText); err != nil {
		return fail(err.Error())
	}
	archivePath := filepath.Join(tmp, archive)
	if err := download(ctx, cur, updateDL+"/v"+next+"/"+archive, archivePath, updateMaxAsset); err != nil {
		return fail(err.Error())
	}
	if err := verifyChecksum(checksums, archive, archivePath); err != nil {
		return fail(err.Error())
	}
	if err := verifySignature(ctx, cur, next, checksums, tmp); err != nil {
		return fail(err.Error())
	}
	bin, err := extractBinary(archivePath, runtime.GOOS)
	if err != nil {
		return fail(err.Error())
	}
	exe, err := os.Executable()
	if err != nil {
		return fail("cannot locate the running binary: " + err.Error())
	}
	// Homebrew and go install put a symlink on PATH; replace the real file.
	exePath, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return fail("cannot resolve the running binary: " + err.Error())
	}
	if err := replaceBinary(runtime.GOOS, exePath, bin); err != nil {
		return fail(err.Error())
	}
	fmt.Printf("updated cavet %s -> %s at %s\n", cur, next, exePath)
	if runtime.GOOS == "windows" {
		fmt.Printf("note: %s.old can be deleted once no cavet process is running\n", exePath)
	}
	return nil
}

// latestRelease resolves the tag_name of the latest GitHub release.
func latestRelease(ctx context.Context, ver string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updateAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "cavet/"+ver)
	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned %s", resp.Status)
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, updateMaxText)).Decode(&release); err != nil {
		return "", fmt.Errorf("github api response unreadable: %v", err)
	}
	if release.TagName == "" {
		return "", errors.New("github api response has no tag_name")
	}
	return release.TagName, nil
}

// download fetches url into dest. Bodies over limit are a hard error, so a
// hostile mirror cannot balloon the temp dir or the memory footprint.
func download(ctx context.Context, ver, url, dest string, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "cavet/"+ver)
	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s: %s (does the release exist? see https://github.com/%s/releases)", url, resp.Status, updateRepo)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("download failed: %s: %v", url, err)
	}
	if n > limit {
		return fmt.Errorf("download failed: %s: larger than %d bytes", url, limit)
	}
	return f.Sync()
}

// verifySignature checks the checksums.txt Sigstore bundle with cosign, pinned
// to the repo's own release workflow. As in the installers, cosign is
// optional: absent, the checksum stands alone with a note on stderr.
func verifySignature(ctx context.Context, curVer, releaseVer, checksums, dir string) error {
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		fmt.Fprintln(os.Stderr, "checksum verified; signature not verified (cosign not installed)")
		return nil
	}
	bundle := filepath.Join(dir, "checksums.txt.sigstore.json")
	url := updateDL + "/v" + releaseVer + "/checksums.txt.sigstore.json"
	if err := download(ctx, curVer, url, bundle, updateMaxText); err != nil {
		return fmt.Errorf("signature bundle unavailable: %v", err)
	}
	// Argument vector only: nothing here ever meets a shell.
	cmd := exec.Command(cosign, "verify-blob",
		"--bundle", bundle,
		"--certificate-identity-regexp", updateIdentityRegexp,
		"--certificate-oidc-issuer", updateOIDCIssuer,
		checksums)
	if _, err := cmd.CombinedOutput(); err != nil {
		return errors.New("signature verification failed, nothing installed")
	}
	return nil
}

// verifyChecksum checks the downloaded archive against its checksums.txt line
// ("sha256<spaces>name") before anything touches it.
func verifyChecksum(checksumsPath, archive, archivePath string) error {
	data, err := os.ReadFile(checksumsPath)
	if err != nil {
		return err
	}
	var want string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == archive {
			want = strings.ToLower(fields[0])
			break
		}
	}
	if want == "" {
		return fmt.Errorf("checksums.txt has no entry for %s", archive)
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("checksum mismatch for %s: download deleted, nothing installed", archive)
	}
	return nil
}

// extractBinary pulls exactly the cavet binary out of the release archive
// (tar.gz; zip on windows). Crafted-entry hardening: no absolute or ".."
// paths, no links or devices, per-entry size capped, entry count bounded.
func extractBinary(archivePath, goos string) ([]byte, error) {
	want := binaryName(goos)
	if goos == "windows" {
		return extractZip(archivePath, want)
	}
	return extractTarGz(archivePath, want)
}

// binaryName is what goreleaser packs inside the archives (.goreleaser.yml
// builds.binary: "cavet", plus the .exe on windows).
func binaryName(goos string) string {
	if goos == "windows" {
		return "cavet.exe"
	}
	return "cavet"
}

func extractTarGz(archivePath, want string) ([]byte, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for i := 0; ; i++ {
		if i >= updateMaxEntries {
			return nil, errors.New("archive has too many entries")
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeDir || hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("archive entry %s is not a regular file", hdr.Name)
		}
		if unsafeArchivePath(hdr.Name) {
			return nil, fmt.Errorf("archive entry %s escapes the extraction directory", hdr.Name)
		}
		if filepath.Base(hdr.Name) != want {
			continue
		}
		return readCapped(tr, hdr.Name)
	}
	return nil, fmt.Errorf("archive has no %s entry", want)
}

func extractZip(archivePath, want string) ([]byte, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if len(r.File) > updateMaxEntries {
		return nil, errors.New("archive has too many entries")
	}
	for _, zf := range r.File {
		mode := zf.Mode()
		if mode.IsDir() {
			continue
		}
		if !mode.IsRegular() {
			return nil, fmt.Errorf("archive entry %s is not a regular file", zf.Name)
		}
		if unsafeArchivePath(zf.Name) {
			return nil, fmt.Errorf("archive entry %s escapes the extraction directory", zf.Name)
		}
		if filepath.Base(zf.Name) != want {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return readCapped(rc, zf.Name)
	}
	return nil, fmt.Errorf("archive has no %s entry", want)
}

// readCapped reads one archive entry, refusing anything beyond updateMaxAsset.
func readCapped(r io.Reader, name string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, updateMaxAsset+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > updateMaxAsset {
		return nil, fmt.Errorf("archive entry %s exceeds %d bytes", name, updateMaxAsset)
	}
	return data, nil
}

// unsafeArchivePath reports entry names that escape the extraction target:
// absolute paths, drive letters, or any ".." element, in both separator
// flavours.
func unsafeArchivePath(name string) bool {
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return true
	}
	if len(name) >= 2 && name[1] == ':' { // windows drive letter
		return true
	}
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}

// assetName maps a platform to its release asset (release workflow naming:
// cavet_<ver>_<os>_<arch>.tar.gz, zip override for windows) and reports false
// for platforms goreleaser does not build (.goreleaser.yml targets).
func assetName(goos, arch, ver string) (string, bool) {
	switch arch {
	case "amd64", "arm64":
	default:
		return "", false
	}
	switch goos {
	case "windows":
		return fmt.Sprintf("cavet_%s_windows_%s.zip", ver, arch), true
	case "darwin", "linux":
		return fmt.Sprintf("cavet_%s_%s_%s.tar.gz", ver, goos, arch), true
	default:
		return "", false
	}
}

// parseVersion parses a strict "major.minor.patch" triple: release versions
// and nothing else. Dev strings, pseudo-versions and rc suffixes fail, which
// is what routes development builds into runUpdate's refusal.
func parseVersion(s string) ([3]int, bool) {
	var v [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		if p == "" {
			return v, false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return v, false
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// compareVersion returns -1, 0 or 1 comparing two triples component-wise.
func compareVersion(a, b [3]int) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// replaceBinary writes the new bytes to a temp file next to exePath (the
// rename must stay on one volume) and swaps it in. goos is a parameter so
// both branches run in tests on any host. Windows cannot delete a running exe
// but can rename it: the old file moves to exePath+".old", rolled back on
// failure, left for the next update to clean on success. Unix renames over it
// atomically.
func replaceBinary(goos, exePath string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(exePath), ".cavet-update-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil { // windows: read-only bit, harmless
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if goos == "windows" {
		old := exePath + ".old"
		os.Remove(old) // best effort: a previous update's leftover
		if err := updateRename(exePath, old); err != nil {
			cleanup()
			return fmt.Errorf("cannot move the running binary aside: %v", err)
		}
		if err := updateRename(tmpName, exePath); err != nil {
			if rb := updateRename(old, exePath); rb != nil {
				return fmt.Errorf("install failed (%v) and rollback failed too: %v", err, rb)
			}
			cleanup()
			return fmt.Errorf("install failed, previous binary restored: %v", err)
		}
		return nil // .old stays: a running exe cannot be deleted on windows
	}
	if err := os.Rename(tmpName, exePath); err != nil {
		cleanup()
		return err
	}
	return nil
}
