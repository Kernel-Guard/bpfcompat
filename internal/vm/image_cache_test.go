package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const testImageBytes = "not really a qcow2, but bytes are bytes"

func serveImage(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(testImageBytes))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/image.qcow2"
}

func imageProfile(url, localPath, pin string) Profile {
	return Profile{ID: "demo", Image: ImageConfig{SourceURL: url, LocalPath: localPath, SHA256: pin}}
}

// dirEntries lists the names in dir (empty if it does not exist).
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// The run directory and the image cache can sit on different filesystems
// (tmpfs /tmp, a bind-mounted project, a separate $HOME). A rename from the
// run dir into the cache then fails with EXDEV after the whole download, so
// the download must be staged next to its final path and renamed within the
// same directory.
func TestEnsureImageAvailableStagesDownloadBesideCachedImage(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "vm", "cache")
	final := filepath.Join(cacheDir, "demo.qcow2")
	orig := renameImageFn
	t.Cleanup(func() { renameImageFn = orig })
	var from, to string
	renameImageFn = func(src, dst string) error {
		from, to = src, dst
		if filepath.Dir(src) != filepath.Dir(dst) {
			// What a cross-filesystem rename returns.
			return &os.LinkError{Op: "rename", Old: src, New: dst, Err: syscall.EXDEV}
		}
		return os.Rename(src, dst)
	}

	got, sum, err := ensureImageAvailable(context.Background(), imageProfile(serveImage(t), final, ""))
	if err != nil {
		t.Fatalf("ensureImageAvailable: %v (rename %s -> %s)", err, from, to)
	}
	if got != final || to != final {
		t.Fatalf("image at %q (renamed to %q), want %q", got, to, final)
	}
	data, err := os.ReadFile(final)
	if err != nil || string(data) != testImageBytes {
		t.Fatalf("cached image = %q, %v", data, err)
	}
	want := sha256.Sum256([]byte(testImageBytes))
	if sum != hex.EncodeToString(want[:]) {
		t.Fatalf("digest %s", sum)
	}
	if names := dirEntries(t, cacheDir); len(names) != 3 { // image, .sha256 sidecar, .lock
		t.Fatalf("cache dir should hold only the image, its sidecar and lock, got %v", names)
	}
}

// If the final rename still fails (EXDEV or anything else), no partial or
// temporary file may remain at or next to the final path.
func TestEnsureImageAvailableRenameFailureLeavesNoPartialImage(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "vm", "cache")
	final := filepath.Join(cacheDir, "demo.qcow2")

	orig := renameImageFn
	t.Cleanup(func() { renameImageFn = orig })
	renameImageFn = func(src, dst string) error {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: syscall.EXDEV}
	}

	_, _, err := ensureImageAvailable(context.Background(), imageProfile(serveImage(t), final, ""))
	if err == nil || !strings.Contains(err.Error(), "cache downloaded image") {
		t.Fatalf("want a cache error, got %v", err)
	}
	if names := dirEntries(t, cacheDir); len(names) != 1 || names[0] != "demo.qcow2.lock" {
		t.Fatalf("cache dir must hold only the lock file after a failed rename, got %v", names)
	}
}

func TestEnsureImageAvailablePinMismatchLeavesNoPartialImage(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "vm", "cache")
	final := filepath.Join(cacheDir, "demo.qcow2")
	pin := strings.Repeat("0", 64)

	_, _, err := ensureImageAvailable(context.Background(), imageProfile(serveImage(t), final, pin))
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("want checksum mismatch, got %v", err)
	}
	if names := dirEntries(t, cacheDir); len(names) != 1 || names[0] != "demo.qcow2.lock" {
		t.Fatalf("cache dir must hold only the lock file after a pin mismatch, got %v", names)
	}
}

// A scratch checkout that links its cache entries to another checkout's cache
// must not rewrite that checkout's files. Writing the sidecar through a
// symlink once replaced another checkout's sidecars with paths into a
// temporary clone. The sidecar is replaced in place; its link target is
// left byte-for-byte unchanged.
func TestChecksumSidecarSymlinkIsReplacedNotFollowed(t *testing.T) {
	other := t.TempDir()
	otherImage := filepath.Join(other, "demo.qcow2")
	if err := os.WriteFile(otherImage, []byte(testImageBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	otherSidecar := otherImage + ".sha256"
	original := "0000  " + otherImage + "\n"
	if err := os.WriteFile(otherSidecar, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	scratch := t.TempDir()
	image := filepath.Join(scratch, "demo.qcow2")
	if err := os.Symlink(otherImage, image); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(otherSidecar, image+".sha256"); err != nil {
		t.Fatal(err)
	}

	sum, err := ensureImageChecksum(image)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(testImageBytes))
	if want := hex.EncodeToString(digest[:]); sum != want {
		t.Fatalf("checksum = %s, want %s", sum, want)
	}

	got, err := os.ReadFile(otherSidecar)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("link target rewritten through the symlink: %q", got)
	}
	fi, err := os.Lstat(image + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("scratch sidecar mode = %v, want a regular file replacing the link", fi.Mode())
	}
	local, err := os.ReadFile(image + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if want := sum + "  " + image + "\n"; string(local) != want {
		t.Fatalf("scratch sidecar = %q, want %q", local, want)
	}
}
