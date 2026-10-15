package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// These tests cover several runs sharing one image cache (built-in profiles
// all use ~/.cache/bpfcompat): concurrent downloads of the same image from
// goroutines and from separate processes, a downloader killed mid-transfer, a
// failing server, an already cached image, and a source whose bytes change
// between requests. The invariant: every caller boots, and records the digest
// of, the one image that was published; a published image is never replaced;
// a pin is checked against the bytes on disk, never against a sidecar or
// another caller's download.

const helperEnv = "BPFCOMPAT_TEST_IMAGE_HELPER"

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// versionedServer serves different bytes on every request ("image v1",
// "image v2", ...), after delay, and counts requests.
type versionedServer struct {
	url      string
	requests atomic.Int32
}

func newVersionedServer(t *testing.T, delay time.Duration) *versionedServer {
	t.Helper()
	vs := &versionedServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := vs.requests.Add(1)
		time.Sleep(delay)
		_, _ = fmt.Fprintf(w, "image v%d %s", n, strings.Repeat("x", 4096))
	}))
	t.Cleanup(srv.Close)
	vs.url = srv.URL + "/image.qcow2"
	return vs
}

type helperResult struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Err    string `json:"err"`
}

// TestImageDownloadHelperProcess is not a test: the cross-process tests re-exec
// the test binary into it to run ensureImageAvailable in a separate process.
func TestImageDownloadHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("helper process only")
	}
	p := imageProfile(os.Getenv("HELPER_URL"), os.Getenv("HELPER_IMAGE"), os.Getenv("HELPER_PIN"))
	path, sum, err := ensureImageAvailable(context.Background(), p)
	res := helperResult{Path: path, SHA256: sum}
	if err != nil {
		res.Err = err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(res)
}

func helperCmd(t *testing.T, url, image, pin string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestImageDownloadHelperProcess$") // #nosec G204 -- the test binary itself.
	cmd.Env = append(os.Environ(), helperEnv+"=1", "HELPER_URL="+url, "HELPER_IMAGE="+image, "HELPER_PIN="+pin)
	return cmd
}

func parseHelper(t *testing.T, out []byte) helperResult {
	t.Helper()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "{") {
			var r helperResult
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatalf("helper output %q: %v", line, err)
			}
			return r
		}
	}
	t.Fatalf("no helper result in %q", out)
	return helperResult{}
}

// assertSinglePublishedImage checks the cache holds exactly the image, its
// sidecar and the lock file, that the sidecar describes the image on disk, and
// that every caller's recorded digest is that image's digest.
func assertSinglePublishedImage(t *testing.T, final string, sums []string) {
	t.Helper()
	data, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("published image: %v", err)
	}
	want := digestOf(data)
	for i, s := range sums {
		if s != want {
			t.Errorf("caller %d recorded sha256 %s, but the published image is %s", i, s, want)
		}
	}
	sidecar, err := os.ReadFile(final + ".sha256")
	if err != nil || !strings.HasPrefix(string(sidecar), want+" ") {
		t.Errorf("sidecar %q does not describe the published image %s (%v)", sidecar, want, err)
	}
	for _, name := range dirEntries(t, filepath.Dir(final)) {
		switch name {
		case filepath.Base(final), filepath.Base(final) + ".sha256", filepath.Base(final) + ".lock":
		default:
			t.Errorf("unexpected file left in the cache: %s", name)
		}
	}
}

func TestConcurrentDownloadsInOneProcessPublishOnce(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		t.Run(fmt.Sprintf("pinned=%v", pinned), func(t *testing.T) {
			vs := newVersionedServer(t, 200*time.Millisecond)
			final := filepath.Join(t.TempDir(), "vm", "cache", "demo.qcow2")
			pin := ""
			if pinned {
				// Only the first response can satisfy the pin.
				pin = digestOf([]byte("image v1 " + strings.Repeat("x", 4096)))
			}
			const callers = 6
			sums := make([]string, callers)
			errs := make([]error, callers)
			var wg sync.WaitGroup
			for i := range callers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, sums[i], errs[i] = ensureImageAvailable(context.Background(), imageProfile(vs.url, final, pin))
				}()
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("caller %d: %v", i, err)
				}
			}
			if got := vs.requests.Load(); got != 1 {
				t.Fatalf("%d downloads of one image; want exactly 1", got)
			}
			assertSinglePublishedImage(t, final, sums)
		})
	}
}

func TestConcurrentDownloadsAcrossProcessesPublishOnce(t *testing.T) {
	vs := newVersionedServer(t, 300*time.Millisecond)
	final := filepath.Join(t.TempDir(), "vm", "cache", "demo.qcow2")
	cmds := []*exec.Cmd{helperCmd(t, vs.url, final, ""), helperCmd(t, vs.url, final, "")}
	outs := make([][]byte, len(cmds))
	var wg sync.WaitGroup
	for i, c := range cmds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], _ = c.Output()
		}()
	}
	wg.Wait()
	sums := make([]string, 0, len(outs))
	for _, out := range outs {
		r := parseHelper(t, out)
		if r.Err != "" {
			t.Fatalf("helper: %s", r.Err)
		}
		sums = append(sums, r.SHA256)
	}
	if got := vs.requests.Load(); got != 1 {
		t.Fatalf("%d downloads across processes; want exactly 1", got)
	}
	assertSinglePublishedImage(t, final, sums)
}

// A published image is never replaced: a later caller whose source now serves
// different bytes keeps using, and recording, the cached image.
func TestCachedImageIsNotReplacedWhenSourceChanges(t *testing.T) {
	vs := newVersionedServer(t, 0)
	final := filepath.Join(t.TempDir(), "vm", "cache", "demo.qcow2")
	_, first, err := ensureImageAvailable(context.Background(), imageProfile(vs.url, final, ""))
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := ensureImageAvailable(context.Background(), imageProfile(vs.url, final, ""))
	if err != nil {
		t.Fatal(err)
	}
	if vs.requests.Load() != 1 || first != second {
		t.Fatalf("requests=%d first=%s second=%s", vs.requests.Load(), first, second)
	}
	assertSinglePublishedImage(t, final, []string{first, second})
}

// A pin is a gate on the bytes on disk. Neither a sidecar claiming the pinned
// digest nor another caller's earlier (unpinned) download can make a cached
// image with other bytes pass.
func TestPinIsCheckedAgainstBytesNotSidecarOrEarlierDownload(t *testing.T) {
	vs := newVersionedServer(t, 0)
	final := filepath.Join(t.TempDir(), "vm", "cache", "demo.qcow2")
	if _, _, err := ensureImageAvailable(context.Background(), imageProfile(vs.url, final, "")); err != nil {
		t.Fatal(err)
	}
	pin := digestOf([]byte("the bytes the profile expects"))
	// Forge the sidecar to claim the pinned digest.
	if err := os.WriteFile(final+".sha256", []byte(pin+"  "+final+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := ensureImageAvailable(context.Background(), imageProfile(vs.url, final, pin))
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("a cached image with other bytes must fail its pin, got %v", err)
	}
}

// A downloader killed mid-transfer (SIGKILL: no cleanup runs) must not block
// or poison the next run: its lock dies with it, its partial file never
// reached the final path, and the next downloader removes the leftover.
func TestDownloaderKilledMidTransferDoesNotPoisonCache(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	full := []byte("complete image " + strings.Repeat("y", 1<<16))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Content-Length", fmt.Sprint(len(full)))
			_, _ = w.Write(full[:len(full)/2])
			w.(http.Flusher).Flush()
			close(started)
			<-release // hang until the test ends
			return
		}
		_, _ = w.Write(full)
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	final := filepath.Join(t.TempDir(), "vm", "cache", "demo.qcow2")

	victim := helperCmd(t, srv.URL+"/image.qcow2", final, "")
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("helper never started downloading")
	}
	// Wait until the partial bytes are on disk, then kill without cleanup.
	deadline := time.Now().Add(10 * time.Second)
	for {
		matches, _ := filepath.Glob(final + ".*.download")
		if len(matches) == 1 {
			if info, err := os.Stat(matches[0]); err == nil && info.Size() > 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no partial download appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := victim.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = victim.Wait()
	if _, err := os.Stat(final); !os.IsNotExist(err) {
		t.Fatalf("a killed download must never reach the final path (stat err=%v)", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, sum, err := ensureImageAvailable(ctx, imageProfile(srv.URL+"/image.qcow2", final, ""))
	if err != nil {
		t.Fatalf("next run after a killed downloader: %v", err)
	}
	if sum != digestOf(full) {
		t.Fatalf("recorded %s, want %s", sum, digestOf(full))
	}
	assertSinglePublishedImage(t, final, []string{sum})
}

// A failing source (HTTP error, connection dropped mid-body) leaves nothing
// at the final path, and the next caller downloads cleanly.
func TestFailedDownloadsLeaveNothingAndNextCallerSucceeds(t *testing.T) {
	full := []byte("good image " + strings.Repeat("z", 8192))
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch requests.Add(1) {
		case 1:
			http.Error(w, "gone", http.StatusNotFound)
		case 2:
			// Promise the full length, send half, drop the connection.
			w.Header().Set("Content-Length", fmt.Sprint(len(full)))
			_, _ = w.Write(full[:len(full)/2])
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		default:
			_, _ = w.Write(full)
		}
	}))
	t.Cleanup(srv.Close)
	final := filepath.Join(t.TempDir(), "vm", "cache", "demo.qcow2")
	p := imageProfile(srv.URL+"/image.qcow2", final, "")

	for i := 1; i <= 2; i++ {
		if _, _, err := ensureImageAvailable(context.Background(), p); err == nil {
			t.Fatalf("attempt %d should fail", i)
		}
		if _, err := os.Stat(final); !os.IsNotExist(err) {
			t.Fatalf("attempt %d left something at the final path", i)
		}
	}
	_, sum, err := ensureImageAvailable(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	assertSinglePublishedImage(t, final, []string{sum})
}

// An already cached image is used without any request.
func TestAlreadyCachedImageMakesNoRequest(t *testing.T) {
	vs := newVersionedServer(t, 0)
	final := filepath.Join(t.TempDir(), "vm", "cache", "demo.qcow2")
	if err := os.MkdirAll(filepath.Dir(final), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(final, []byte("pre-cached"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, sum, err := ensureImageAvailable(context.Background(), imageProfile(vs.url, final, digestOf([]byte("pre-cached"))))
	if err != nil || sum != digestOf([]byte("pre-cached")) || vs.requests.Load() != 0 {
		t.Fatalf("sum=%s err=%v requests=%d", sum, err, vs.requests.Load())
	}
}

// Waiting for another downloader's lock honours the caller's context.
func TestLockWaitHonoursContext(t *testing.T) {
	final := filepath.Join(t.TempDir(), "vm", "cache", "demo.qcow2")
	if err := os.MkdirAll(filepath.Dir(final), 0o750); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockImage(context.Background(), final)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err = ensureImageAvailable(ctx, imageProfile("http://127.0.0.1:1/never", final, ""))
	if err == nil || !strings.Contains(err.Error(), "image lock") {
		t.Fatalf("want a lock-wait error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("lock wait ignored the context deadline")
	}
}
