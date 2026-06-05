package api

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/erenari/bpfcompat/internal/runner"
	"github.com/erenari/bpfcompat/pkg/schema"
)

func TestValidateStartRejectsUnknownProfile(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")

	s := &Server{cfg: Config{
		WorkDir:            t.TempDir(),
		DefaultConcurrency: 1,
		DefaultTimeout:     2 * time.Minute,
	}}

	req := newValidateMultipartRequest(t, "/api/validate/start", "no-such-profile")
	rec := httptest.NewRecorder()
	s.handleValidateStart(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown profile, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "unknown profile id") {
		t.Fatalf("expected unknown profile id error, got body=%s", rec.Body.String())
	}
}

func TestValidateStartEnforcesConcurrencyAndTimeoutCaps(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(envMaxValidateConcurrency, "1")
	t.Setenv(envMaxValidateTimeout, "45s")

	profileID := firstProfileIDForAsyncValidateTest(t)
	s := &Server{cfg: Config{
		WorkDir:            t.TempDir(),
		DefaultConcurrency: 1,
		DefaultTimeout:     30 * time.Second,
	}}

	reqConcurrency := newValidateMultipartRequestWithValues(t, "/api/validate/start", profileID, "30s", "2")
	recConcurrency := httptest.NewRecorder()
	s.handleValidateStart(recConcurrency, reqConcurrency)
	if recConcurrency.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for concurrency cap, got %d body=%s", recConcurrency.Code, recConcurrency.Body.String())
	}

	reqTimeout := newValidateMultipartRequestWithValues(t, "/api/validate/start", profileID, "2m", "1")
	recTimeout := httptest.NewRecorder()
	s.handleValidateStart(recTimeout, reqTimeout)
	if recTimeout.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for timeout cap, got %d body=%s", recTimeout.Code, recTimeout.Body.String())
	}
}

func TestValidateStartQueueCapacity(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(envMaxActiveValidateJobs, "1")
	t.Setenv(envMaxQueuedValidateJobs, "0")

	profileID := firstProfileIDForAsyncValidateTest(t)
	workDir := t.TempDir()
	s := &Server{cfg: Config{
		WorkDir:            workDir,
		DefaultConcurrency: 1,
		DefaultTimeout:     2 * time.Minute,
	}}

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	closeRelease := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	t.Cleanup(func() {
		closeRelease()
		s.inflight.Wait()
	})

	s.runValidate = func(ctx context.Context, cfg runner.Config) (runner.RunResult, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return runner.RunResult{
			RunDir:   filepath.Join(workDir, "runs", "done"),
			ExitCode: 0,
			Report: schema.ReportV01{
				SchemaVersion: "v0.1",
				Run: schema.RunInfo{
					ID:        "run-done",
					StartedAt: time.Now().UTC().Format(time.RFC3339),
				},
				Paths: schema.Paths{
					RunDir: filepath.Join(workDir, "runs", "done"),
					JSON:   filepath.Join(workDir, "reports", "done.json"),
				},
				Summary: schema.SummaryInfo{Status: "pass"},
			},
		}, nil
	}

	req1 := newValidateMultipartRequestWithValues(t, "/api/validate/start", profileID, "30s", "1")
	rec1 := httptest.NewRecorder()
	s.handleValidateStart(rec1, req1)
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("expected first request 202, got %d body=%s", rec1.Code, rec1.Body.String())
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first validate job did not start in time")
	}

	req2 := newValidateMultipartRequestWithValues(t, "/api/validate/start", profileID, "30s", "1")
	rec2 := httptest.NewRecorder()
	s.handleValidateStart(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		closeRelease()
		t.Fatalf("expected second request 429, got %d body=%s", rec2.Code, rec2.Body.String())
	}

	closeRelease()
}

func TestSanitizeExtraClangFlags(t *testing.T) {
	t.Setenv(envSourceCompileAllowExtraFlags, "false")
	if _, err := sanitizeExtraClangFlags("-DTEST=1"); err == nil {
		t.Fatal("expected error when clang flags are disabled")
	}

	t.Setenv(envSourceCompileAllowExtraFlags, "true")
	if _, err := sanitizeExtraClangFlags("-Winvalid-flag"); err == nil {
		t.Fatal("expected invalid clang flag to be rejected")
	}

	flags, err := sanitizeExtraClangFlags("-DTEST=1 -UFOO")
	if err != nil {
		t.Fatalf("expected safe flags to pass, got error: %v", err)
	}
	if len(flags) != 2 || flags[0] != "-DTEST=1" || flags[1] != "-UFOO" {
		t.Fatalf("unexpected sanitized flags: %#v", flags)
	}
}

func newValidateMultipartRequestWithValues(t *testing.T, path, profileID, timeout, concurrency string) *http.Request {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	fileWriter, err := writer.CreateFormFile("artifact_file", "demo.bpf.o")
	if err != nil {
		t.Fatalf("create multipart artifact_file: %v", err)
	}
	if _, err := fileWriter.Write([]byte("ELF-DATA")); err != nil {
		t.Fatalf("write multipart artifact_file: %v", err)
	}
	if err := writer.WriteField("artifact_name", "demo"); err != nil {
		t.Fatalf("write artifact_name: %v", err)
	}
	if err := writer.WriteField("artifact_version", "v1.0.0"); err != nil {
		t.Fatalf("write artifact_version: %v", err)
	}
	if err := writer.WriteField("profiles", profileID); err != nil {
		t.Fatalf("write profiles: %v", err)
	}
	if err := writer.WriteField("required_profiles", profileID); err != nil {
		t.Fatalf("write required_profiles: %v", err)
	}
	if err := writer.WriteField("timeout", timeout); err != nil {
		t.Fatalf("write timeout: %v", err)
	}
	if err := writer.WriteField("concurrency", concurrency); err != nil {
		t.Fatalf("write concurrency: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}
