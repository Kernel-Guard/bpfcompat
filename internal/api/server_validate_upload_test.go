package api

import (
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/runner"
)

// uploadEntries lists what is left under workdir/uploads. A missing
// directory counts as empty.
func uploadEntries(t *testing.T, workDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(workDir, "uploads"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read uploads dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func assertNoUploads(t *testing.T, workDir string) {
	t.Helper()
	if left := uploadEntries(t, workDir); len(left) > 0 {
		t.Fatalf("expected workdir/uploads to be empty, found %v", left)
	}
}

func newUploadTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	workDir := t.TempDir()
	s := &Server{cfg: Config{
		WorkDir:            workDir,
		DefaultConcurrency: 1,
		DefaultTimeout:     2 * time.Minute,
	}}
	t.Cleanup(s.inflight.Wait)
	return s, workDir
}

func runnerMustNotRun(t *testing.T) func(context.Context, runner.Config) (runner.RunResult, error) {
	return func(context.Context, runner.Config) (runner.RunResult, error) {
		t.Errorf("runner must not be reached")
		return runner.RunResult{}, nil
	}
}

// streamingValidateRequest builds a multipart validate request whose
// artifact_file part is size bytes, streamed through a pipe so the test
// never holds the whole body in memory.
func streamingValidateRequest(path string, size int64, extra map[string]string) *http.Request {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		fw, err := mw.CreateFormFile("artifact_file", "big.bpf.o")
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		chunk := make([]byte, 64<<10)
		for written := int64(0); written < size; {
			n := int64(len(chunk))
			if size-written < n {
				n = size - written
			}
			if _, err := fw.Write(chunk[:n]); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			written += n
		}
		for k, v := range extra {
			_ = mw.WriteField(k, v)
		}
		_ = mw.Close()
		_ = pw.Close()
	}()
	req := httptest.NewRequest(http.MethodPost, path, pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func TestValidateUploadOversizedBodyRejectedWith413(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(envMaxUploadBytes, strconv.Itoa(1<<20))

	for _, tc := range []struct {
		name   string
		path   string
		handle func(*Server, http.ResponseWriter, *http.Request)
	}{
		{"sync", "/api/validate", (*Server).handleValidate},
		{"async", "/api/validate/start", (*Server).handleValidateStart},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, workDir := newUploadTestServer(t)
			s.runValidate = runnerMustNotRun(t)
			req := streamingValidateRequest(tc.path, 4<<20, nil)
			rec := httptest.NewRecorder()
			tc.handle(s, rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("expected 413, got %d body=%s", rec.Code, rec.Body.String())
			}
			assertNoUploads(t, workDir)
		})
	}
}

func TestValidateUploadDefaultCapRejectsBodyAboveDefault(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	s, workDir := newUploadTestServer(t)
	s.runValidate = runnerMustNotRun(t)
	req := streamingValidateRequest("/api/validate/start", defaultMaxUploadBytes+(1<<20), nil)
	rec := httptest.NewRecorder()
	s.handleValidateStart(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 above the default cap, got %d body=%s", rec.Code, rec.Body.String())
	}
	assertNoUploads(t, workDir)
}

func TestValidateUploadRemovedOnBadRequest(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	profileID := firstProfileIDForAsyncValidateTest(t)
	for _, tc := range []struct {
		name   string
		path   string
		handle func(*Server, http.ResponseWriter, *http.Request)
	}{
		{"sync", "/api/validate", (*Server).handleValidate},
		{"async", "/api/validate/start", (*Server).handleValidateStart},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, workDir := newUploadTestServer(t)
			s.runValidate = runnerMustNotRun(t)
			req := streamingValidateRequest(tc.path, 64<<10, map[string]string{
				"profiles": profileID,
				"timeout":  "not-a-duration",
			})
			rec := httptest.NewRecorder()
			tc.handle(s, rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
			}
			assertNoUploads(t, workDir)
		})
	}
}

func TestValidateStartCapacityRejectLeavesNoUpload(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(envMaxActiveValidateJobs, "1")
	t.Setenv(envMaxQueuedValidateJobs, "0")
	profileID := firstProfileIDForAsyncValidateTest(t)
	s, workDir := newUploadTestServer(t)
	s.runValidate = runnerMustNotRun(t)
	s.validateJobs.jobs = map[string]*validateJob{
		"val-busy": {JobID: "val-busy", State: "running"},
	}

	req := newValidateMultipartRequest(t, "/api/validate/start", profileID)
	rec := httptest.NewRecorder()
	s.handleValidateStart(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", rec.Code, rec.Body.String())
	}
	assertNoUploads(t, workDir)
}

func TestValidateUploadAuthFailureLeavesNoUpload(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "false")
	t.Setenv(envWriteAPIKey, "upload-test-key")
	profileID := firstProfileIDForAsyncValidateTest(t)
	s, workDir := newUploadTestServer(t)
	s.runValidate = runnerMustNotRun(t)

	req := newValidateMultipartRequest(t, "/api/validate/start", profileID)
	rec := httptest.NewRecorder()
	s.handleValidateStart(rec, req)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("expected 401/403, got %d body=%s", rec.Code, rec.Body.String())
	}
	assertNoUploads(t, workDir)
}

func TestValidateSyncUploadRemovedAfterRunnerError(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	profileID := firstProfileIDForAsyncValidateTest(t)
	s, workDir := newUploadTestServer(t)
	var seenArtifact string
	s.runValidate = func(_ context.Context, cfg runner.Config) (runner.RunResult, error) {
		seenArtifact = cfg.ArtifactPath
		if _, err := os.Stat(cfg.ArtifactPath); err != nil {
			t.Errorf("artifact must exist while the runner executes: %v", err)
		}
		return runner.RunResult{}, errors.New("boom")
	}
	rec := httptest.NewRecorder()
	s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d body=%s", rec.Code, rec.Body.String())
	}
	if seenArtifact == "" {
		t.Fatalf("runner was not invoked")
	}
	assertNoUploads(t, workDir)
}

func TestValidateAsyncUploadRemovedAfterFailedTerminalState(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	profileID := firstProfileIDForAsyncValidateTest(t)
	s, workDir := newUploadTestServer(t)
	s.runValidate = func(_ context.Context, cfg runner.Config) (runner.RunResult, error) {
		if _, err := os.Stat(cfg.ArtifactPath); err != nil {
			t.Errorf("artifact must exist while the runner executes: %v", err)
		}
		return runner.RunResult{}, errors.New("boom")
	}
	rec := httptest.NewRecorder()
	s.handleValidateStart(rec, newValidateMultipartRequest(t, "/api/validate/start", profileID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	s.inflight.Wait()
	assertNoUploads(t, workDir)
}

func TestRegistryArtifactUploadOversizedBodyRejectedWith413(t *testing.T) {
	t.Setenv(envMaxUploadBytes, strconv.Itoa(1<<20))
	s, _ := newUploadTestServer(t)
	req := streamingValidateRequest("/api/registry/artifacts/upload", 4<<20, nil)
	rec := httptest.NewRecorder()
	s.handleRegistryArtifactUpload(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// Successful runs persist local registry history whose artifact_path /
// manifest_path point into workdir/uploads (runtime fetch/execute read them
// later), so they are retained — but only the newest
// maxRetainedValidateUploads directories survive.
func TestValidateSuccessfulUploadsRetainedButBounded(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	profileID := firstProfileIDForAsyncValidateTest(t)
	s, workDir := newUploadTestServer(t)
	var lastArtifact string
	s.runValidate = func(_ context.Context, cfg runner.Config) (runner.RunResult, error) {
		lastArtifact = cfg.ArtifactPath
		return runner.RunResult{}, nil
	}

	total := maxRetainedValidateUploads + 3
	for i := 0; i < total; i++ {
		rec := httptest.NewRecorder()
		s.handleValidate(rec, newValidateMultipartRequest(t, "/api/validate", profileID))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d body=%s", i, rec.Code, rec.Body.String())
		}
		// Distinct mtimes keep the "newest first" ordering deterministic.
		time.Sleep(2 * time.Millisecond)
	}
	if got := len(uploadEntries(t, workDir)); got != maxRetainedValidateUploads {
		t.Fatalf("expected %d retained upload dirs, got %d", maxRetainedValidateUploads, got)
	}
	if _, err := os.Stat(lastArtifact); err != nil {
		t.Fatalf("newest successful upload must be retained: %v", err)
	}

	// Async success: the upload survives the terminal state and the bound
	// still holds.
	rec := httptest.NewRecorder()
	s.handleValidateStart(rec, newValidateMultipartRequest(t, "/api/validate/start", profileID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
	s.inflight.Wait()
	if _, err := os.Stat(lastArtifact); err != nil {
		t.Fatalf("async successful upload must be retained: %v", err)
	}
	if got := len(uploadEntries(t, workDir)); got != maxRetainedValidateUploads {
		t.Fatalf("expected %d retained upload dirs after async run, got %d", maxRetainedValidateUploads, got)
	}
}
