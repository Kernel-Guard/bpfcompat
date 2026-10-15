package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// gzipZeroTar returns a gzip'd tar holding `entries` regular files of
// `entrySize` zero bytes each: a small upload that expands a thousandfold.
func gzipZeroTar(t *testing.T, entries int, entrySize int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(gz)
	for i := 0; i < entries; i++ {
		hdr := &tar.Header{
			Name:     fmt.Sprintf("blobs/sha256/zero%03d", i),
			Mode:     0o600,
			Size:     entrySize,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(tw, zeroReader{}, entrySize); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newValidateUploadRequest(t *testing.T, path, profileID, fileName string, content []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	fw, err := writer.CreateFormFile("artifact_file", fileName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"artifact_name":     "upload",
		"artifact_version":  "v1.0.0",
		"profiles":          profileID,
		"required_profiles": profileID,
		"timeout":           "1m",
		"concurrency":       "1",
	} {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

// dirBytes sums the sizes of the regular files under root.
func dirBytes(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// TestValidateStartRejectsGzipBombUpload drives the real runner through
// /api/validate/start with a ~1 MiB gzip'd tar that expands to 1 GiB. Every
// gzip upload is routed to the OCI-archive path, which used to expand it under
// os.TempDir with the 8 GiB CLI ceiling. The API must reject it early, keep the
// peak bytes written to the temp dir bounded, clean up, and not leak paths.
func TestValidateStartRejectsGzipBombUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 1 GiB-expanding gzip bomb")
	}
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(envRedactRuntime, "true")
	tmpRoot := filepath.Join(t.TempDir(), "tmp")
	if err := os.MkdirAll(tmpRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmpRoot)

	// 64 entries x 16 MiB = 1 GiB of zeros.
	const expanded = int64(64 * 16 << 20)
	bomb := gzipZeroTar(t, 64, 16<<20)
	t.Logf("bomb upload = %d bytes, expands to %d bytes (x%d)", len(bomb), expanded, expanded/int64(len(bomb)))

	profileID := firstProfileIDForAsyncValidateTest(t)
	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir, DefaultConcurrency: 1, DefaultTimeout: 2 * time.Minute}}
	t.Cleanup(s.inflight.Wait)

	// Sample the temp dir while the job runs to bound peak disk usage.
	stop := make(chan struct{})
	peakCh := make(chan int64, 1)
	go func() {
		var peak int64
		for {
			if n := dirBytes(tmpRoot); n > peak {
				peak = n
			}
			select {
			case <-stop:
				peakCh <- peak
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()

	start := time.Now()
	rec := httptest.NewRecorder()
	s.handleValidateStart(rec, newValidateUploadRequest(t, "/api/validate/start", profileID, "gadget.tar.gz", bomb))
	if rec.Code != http.StatusAccepted {
		close(stop)
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	var started validateStartResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil {
		close(stop)
		t.Fatal(err)
	}

	var final validateStatusResponse
	deadline := time.Now().Add(2 * time.Minute)
	for {
		sr := httptest.NewRecorder()
		s.handleValidateStatus(sr, httptest.NewRequest(http.MethodGet, "/api/validate/status?job_id="+started.JobID, http.NoBody))
		if err := json.Unmarshal(sr.Body.Bytes(), &final); err != nil {
			close(stop)
			t.Fatal(err)
		}
		if final.State == "completed" || final.State == "failed" {
			break
		}
		if time.Now().After(deadline) {
			close(stop)
			t.Fatalf("timed out; last state=%q", final.State)
		}
		time.Sleep(10 * time.Millisecond)
	}
	elapsed := time.Since(start)
	close(stop)
	peak := <-peakCh
	t.Logf("state=%s elapsed=%s peak temp bytes=%d error=%q", final.State, elapsed, peak, final.Error)

	if final.State != "failed" {
		t.Fatalf("expected failed job, got %q", final.State)
	}
	if !strings.Contains(final.Error, "expanded-size limit") {
		t.Fatalf("expected an expanded-size limit error, got %q", final.Error)
	}
	// Upload ~1 MiB x 64 => the ratio cap (well under the 512 MiB absolute
	// cap) binds. Allow one 16 MiB entry of slack for the sampled measurement.
	if limit := int64(len(bomb))*64 + (16 << 20); peak > limit {
		t.Fatalf("peak temp-dir usage %d bytes exceeds API expansion bound %d", peak, limit)
	}
	for _, leak := range []string{tmpRoot, workDir} {
		if strings.Contains(final.Error, leak) {
			t.Fatalf("job error leaks host path %q: %q", leak, final.Error)
		}
	}
	left, _ := filepath.Glob(filepath.Join(tmpRoot, "bpfcompat-oci*"))
	if len(left) != 0 {
		t.Fatalf("partial OCI extraction left behind: %v", left)
	}
	if elapsed > 30*time.Second {
		t.Fatalf("rejection took %s; expected an early abort", elapsed)
	}
}
