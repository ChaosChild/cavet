package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVersionCompare(t *testing.T) {
	cases := []struct {
		in     string
		want   [3]int
		parses bool
	}{
		{"0.1.0", [3]int{0, 1, 0}, true},
		{"1.2.3", [3]int{1, 2, 3}, true},
		{"10.20.30", [3]int{10, 20, 30}, true},
		{"dev", [3]int{}, false},
		{"", [3]int{}, false},
		{"1.2", [3]int{}, false},
		{"1.2.3.4", [3]int{}, false},
		{"1.2.3-rc1", [3]int{}, false},
		{"0.0.0-20260831115634-1fe5bfa8e191+dirty", [3]int{}, false},
		{"a.b.c", [3]int{}, false},
		{"1..3", [3]int{}, false},
		{"1.2.x", [3]int{}, false},
		{"+1.2.3", [3]int{}, false},
	}
	for _, c := range cases {
		got, ok := parseVersion(c.in)
		if ok != c.parses || (ok && got != c.want) {
			t.Errorf("parseVersion(%q): got (%v, %v) want (%v, %v)", c.in, got, ok, c.want, c.parses)
		}
	}
	a, _ := parseVersion("0.1.0")
	eq, _ := parseVersion("0.1.0")
	older, _ := parseVersion("0.0.9")
	newer, _ := parseVersion("0.2.0")
	muchNewer, _ := parseVersion("1.0.0")
	for _, c := range []struct {
		x, y [3]int
		want int
	}{{a, eq, 0}, {a, older, 1}, {a, newer, -1}, {a, muchNewer, -1}, {muchNewer, a, 1}} {
		if got := compareVersion(c.x, c.y); got != c.want {
			t.Errorf("compareVersion(%v, %v): got %d want %d", c.x, c.y, got, c.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	cases := []struct {
		goos, arch string
		want       string
		ok         bool
	}{
		{"windows", "amd64", "cavet_0.2.0_windows_amd64.zip", true},
		{"windows", "arm64", "cavet_0.2.0_windows_arm64.zip", true},
		{"darwin", "amd64", "cavet_0.2.0_darwin_amd64.tar.gz", true},
		{"darwin", "arm64", "cavet_0.2.0_darwin_arm64.tar.gz", true},
		{"linux", "amd64", "cavet_0.2.0_linux_amd64.tar.gz", true},
		{"linux", "arm64", "cavet_0.2.0_linux_arm64.tar.gz", true},
		{"linux", "386", "", false},
		{"linux", "riscv64", "", false},
		{"freebsd", "amd64", "", false},
		{"plan9", "arm64", "", false},
	}
	for _, c := range cases {
		got, ok := assetName(c.goos, c.arch, "0.2.0")
		if ok != c.ok || got != c.want {
			t.Errorf("assetName(%s, %s): got (%q, %v) want (%q, %v)", c.goos, c.arch, got, ok, c.want, c.ok)
		}
	}
}

func TestUnsafeArchivePath(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"cavet", false},
		{"./cavet", false},
		{"sub/dir/cavet", false},
		{"a..b/cavet", false},
		{"..", true},
		{"../evil.txt", true},
		{"sub/../evil.txt", true},
		{`sub\..\evil.txt`, true},
		{"/abs/cavet", true},
		{`\abs\cavet`, true},
		{`C:\cavet`, true},
		{`C:cavet`, true},
	} {
		if got := unsafeArchivePath(c.in); got != c.want {
			t.Errorf("unsafeArchivePath(%q): got %v want %v", c.in, got, c.want)
		}
	}
}

// archiveEntry is one packed file for the archive builders: regular unless
// link is set (symlink pointing at link).
type archiveEntry struct {
	name    string
	content string
	link    string
}

func writeTarGz(t *testing.T, path string, entries []archiveEntry) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name}
		if e.link != "" {
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.link
		} else {
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(e.content))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeZip(t *testing.T, path string, entries []archiveEntry) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.link != "" {
			hdr.SetMode(os.ModeSymlink | 0o777)
		} else {
			hdr.SetMode(0o755)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		content := e.content
		if e.link != "" {
			content = e.link
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExtractTarGz(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.tar.gz")
	writeTarGz(t, path, []archiveEntry{
		{name: "LICENSE", content: "MIT"},
		{name: "README.md", content: "# cavet"},
		{name: "cavet", content: "binary-bytes"},
	})
	got, err := extractBinary(path, "linux")
	if err != nil || string(got) != "binary-bytes" {
		t.Fatalf("happy path: got %q, %v", got, err)
	}

	// The hostile entry comes first: extraction stops at the first match, so
	// the later binary must not mask what precedes it.
	writeTarGz(t, path, []archiveEntry{
		{name: "../evil.txt", content: "nope"},
		{name: "cavet", content: "b"},
	})
	if _, err := extractBinary(path, "linux"); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("traversal entry must be rejected, got %v", err)
	}

	writeTarGz(t, path, []archiveEntry{{name: "cavet", link: "/etc/passwd"}})
	if _, err := extractBinary(path, "linux"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink entry must be rejected, got %v", err)
	}

	writeTarGz(t, path, []archiveEntry{{name: "LICENSE", content: "MIT"}})
	if _, err := extractBinary(path, "linux"); err == nil || !strings.Contains(err.Error(), "no cavet entry") {
		t.Fatalf("missing binary must be an error, got %v", err)
	}

	origCap := updateMaxAsset
	t.Cleanup(func() { updateMaxAsset = origCap })
	updateMaxAsset = 8
	writeTarGz(t, path, []archiveEntry{{name: "cavet", content: "0123456789"}})
	if _, err := extractBinary(path, "linux"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("size cap must trigger, got %v", err)
	}

	origEntries := updateMaxEntries
	t.Cleanup(func() { updateMaxEntries = origEntries })
	updateMaxEntries = 1
	writeTarGz(t, path, []archiveEntry{{name: "LICENSE", content: "MIT"}, {name: "cavet", content: "b"}})
	if _, err := extractBinary(path, "linux"); err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("entry bound must trigger, got %v", err)
	}
}

func TestExtractZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.zip")
	writeZip(t, path, []archiveEntry{
		{name: "LICENSE", content: "MIT"},
		{name: "cavet.exe", content: "binary-bytes"},
	})
	got, err := extractBinary(path, "windows")
	if err != nil || string(got) != "binary-bytes" {
		t.Fatalf("happy path: got %q, %v", got, err)
	}

	writeZip(t, path, []archiveEntry{
		{name: "../evil.exe", content: "nope"},
		{name: "cavet.exe", content: "b"},
	})
	if _, err := extractBinary(path, "windows"); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("traversal entry must be rejected, got %v", err)
	}

	writeZip(t, path, []archiveEntry{{name: "cavet.exe", link: `C:\Windows\system32`}})
	if _, err := extractBinary(path, "windows"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink entry must be rejected, got %v", err)
	}

	origCap := updateMaxAsset
	t.Cleanup(func() { updateMaxAsset = origCap })
	updateMaxAsset = 8
	writeZip(t, path, []archiveEntry{{name: "cavet.exe", content: "0123456789"}})
	if _, err := extractBinary(path, "windows"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("size cap must trigger, got %v", err)
	}
}

// writeChecksums stores content as archive in dir and a matching checksums.txt
// beside it, returning the checksums path.
func writeChecksums(t *testing.T, dir, archive, content string) string {
	t.Helper()
	archivePath := filepath.Join(dir, archive)
	if err := os.WriteFile(archivePath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	checksumsPath := filepath.Join(dir, "checksums.txt")
	line := hex.EncodeToString(sum[:]) + "  " + archive + "\n"
	if err := os.WriteFile(checksumsPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	return checksumsPath
}

func TestVerifyChecksum(t *testing.T) {
	dir := t.TempDir()
	archive := "cavet_0.2.0_linux_amd64.tar.gz"
	checksums := writeChecksums(t, dir, archive, "archive-bytes")
	if err := verifyChecksum(checksums, archive, filepath.Join(dir, archive)); err != nil {
		t.Fatalf("matching checksum must pass, got %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, archive), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := verifyChecksum(checksums, archive, filepath.Join(dir, archive))
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered archive must fail, got %v", err)
	}

	err = verifyChecksum(checksums, "cavet_0.2.0_windows_amd64.zip", filepath.Join(dir, "cavet_0.2.0_windows_amd64.zip"))
	if err == nil || !strings.Contains(err.Error(), "no entry") {
		t.Fatalf("unknown asset must fail, got %v", err)
	}
}

func TestReplaceBinary(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		dir := t.TempDir()
		exePath := filepath.Join(dir, binaryName(goos))
		if err := os.WriteFile(exePath, []byte("old-bytes"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := replaceBinary(goos, exePath, []byte("new-bytes")); err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		got, err := os.ReadFile(exePath)
		if err != nil || string(got) != "new-bytes" {
			t.Fatalf("%s: new binary not in place: %q, %v", goos, got, err)
		}
		if goos == "windows" {
			old, err := os.ReadFile(exePath + ".old")
			if err != nil || string(old) != "old-bytes" {
				t.Fatalf("windows: previous binary must sit at .old: %q, %v", old, err)
			}
		} else if _, err := os.Stat(exePath + ".old"); !os.IsNotExist(err) {
			t.Fatalf("%s: no .old expected, got %v", goos, err)
		}
	}
}

func TestReplaceBinaryWindowsRollback(t *testing.T) {
	origRename := updateRename
	t.Cleanup(func() { updateRename = origRename })

	dir := t.TempDir()
	exePath := filepath.Join(dir, "cavet.exe")
	if err := os.WriteFile(exePath, []byte("old-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Fail exactly the install rename (tmp -> exePath); the .old move and the
	// rollback still go through os.Rename.
	updateRename = func(from, to string) error {
		if to == exePath && from != exePath+".old" {
			return errors.New("forced install failure")
		}
		return os.Rename(from, to)
	}
	err := replaceBinary("windows", exePath, []byte("new-bytes"))
	if err == nil || !strings.Contains(err.Error(), "previous binary restored") {
		t.Fatalf("rollback must restore, got %v", err)
	}
	got, rerr := os.ReadFile(exePath)
	if rerr != nil || string(got) != "old-bytes" {
		t.Fatalf("original binary must be back: %q, %v", got, rerr)
	}
	if _, serr := os.Stat(exePath + ".old"); !os.IsNotExist(serr) {
		t.Fatalf("rollback must remove .old, got %v", serr)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".cavet-update-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temp file must be cleaned up, got %v", leftovers)
	}
}

func TestLatestRelease(t *testing.T) {
	origAPI := updateAPI
	t.Cleanup(func() { updateAPI = origAPI })

	var gotAccept, gotUA string
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		gotUA = r.Header.Get("User-Agent")
		fmt.Fprint(w, `{"tag_name": "v0.2.0", "name": "cavet 0.2.0"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	updateAPI = srv.URL + "/releases/latest"
	tag, err := latestRelease(t.Context(), "0.1.0")
	if err != nil || tag != "v0.2.0" {
		t.Fatalf("got %q, %v", tag, err)
	}
	if gotAccept != "application/vnd.github+json" || gotUA != "cavet/0.1.0" {
		t.Fatalf("headers: Accept %q UA %q", gotAccept, gotUA)
	}

	updateAPI = srv.URL + "/missing"
	if _, err := latestRelease(t.Context(), "0.1.0"); err == nil || !strings.Contains(err.Error(), "github api returned") {
		t.Fatalf("non-200 must fail, got %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<html>not json</html>`)
	}))
	defer bad.Close()
	updateAPI = bad.URL
	if _, err := latestRelease(t.Context(), "0.1.0"); err == nil {
		t.Fatal("malformed JSON must fail")
	}
}

func TestUpdateShortCircuits(t *testing.T) {
	origVersion, origAPI, origDL := version, updateAPI, updateDL
	t.Cleanup(func() { version, updateAPI, updateDL = origVersion, origAPI, origDL })

	downloads := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"tag_name": "v0.2.0"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		downloads++
		http.Error(w, "asset downloads must not happen in these paths", http.StatusTeapot)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	updateAPI = srv.URL + "/api/releases/latest"
	updateDL = srv.URL + "/download"

	version = "0.1.0"
	if err := runUpdate(true); err != nil {
		t.Fatalf("--check with an update available must exit 0: %v", err)
	}
	if downloads != 0 {
		t.Fatalf("--check must not download, got %d downloads", downloads)
	}

	version = "0.2.0"
	if err := runUpdate(false); err != nil {
		t.Fatalf("up to date must exit 0: %v", err)
	}
	version = "0.3.0"
	if err := runUpdate(false); err != nil {
		t.Fatalf("newer than latest must exit 0: %v", err)
	}
	if downloads != 0 {
		t.Fatalf("up-to-date runs must not download, got %d downloads", downloads)
	}

	version = "dev"
	err := runUpdate(true)
	if err == nil || !strings.Contains(err.Error(), "development or unversioned") {
		t.Fatalf("dev build must refuse before any network use, got %v", err)
	}
}

func TestDownloadCapsAndErrors(t *testing.T) {
	origDL := updateDL
	t.Cleanup(func() { updateDL = origDL })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			fmt.Fprint(w, "0123456789")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	updateDL = srv.URL

	dest := filepath.Join(t.TempDir(), "out")
	if err := download(t.Context(), "0.1.0", srv.URL+"/big", dest, 5); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("over-cap body must fail, got %v", err)
	}
	if err := download(t.Context(), "0.1.0", srv.URL+"/big", dest, 10); err != nil {
		t.Fatalf("at-cap body must pass, got %v", err)
	}
	if err := download(t.Context(), "0.1.0", srv.URL+"/missing", dest, 10); err == nil || !strings.Contains(err.Error(), "download failed") {
		t.Fatalf("404 must fail, got %v", err)
	}
}
