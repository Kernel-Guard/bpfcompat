package api

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/erenari/bpfcompat/internal/runner"
	"github.com/erenari/bpfcompat/pkg/schema"
)

func TestValidateAsyncJobLifecycle(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")

	profileID := firstProfileIDForAsyncValidateTest(t)
	workDir := t.TempDir()
	s := &Server{cfg: Config{
		WorkDir:            workDir,
		DefaultConcurrency: 1,
		DefaultTimeout:     2 * time.Minute,
	}}
	t.Cleanup(s.inflight.Wait)

	s.runValidate = func(ctx context.Context, cfg runner.Config) (runner.RunResult, error) {
		if cfg.Progress != nil {
			cfg.Progress(runner.ProgressUpdate{
				Stage:             runner.ProgressStageValidateTargets,
				Message:           "Running profile " + profileID,
				TotalProfiles:     1,
				CompletedProfiles: 0,
				ProfileID:         profileID,
				ProfileStatus:     "running",
			})
			cfg.Progress(runner.ProgressUpdate{
				Stage:             runner.ProgressStageValidateTargets,
				Message:           "Completed profile " + profileID + " (1/1)",
				TotalProfiles:     1,
				CompletedProfiles: 1,
				ProfileID:         profileID,
				ProfileStatus:     "pass",
			})
			cfg.Progress(runner.ProgressUpdate{
				Stage:   runner.ProgressStageWriteReport,
				Message: "Writing reports",
			})
			cfg.Progress(runner.ProgressUpdate{
				Stage:   runner.ProgressStageCompleted,
				Message: "Validation completed",
			})
		}

		return runner.RunResult{
			RunDir:   filepath.Join(workDir, "runs", "demo"),
			ExitCode: 0,
			Report: schema.ReportV01{
				SchemaVersion: "v0.1",
				Run: schema.RunInfo{
					ID:        "run-demo",
					StartedAt: time.Now().UTC().Format(time.RFC3339),
				},
				Paths: schema.Paths{
					RunDir:   filepath.Join(workDir, "runs", "demo"),
					JSON:     filepath.Join(workDir, "reports", "demo.json"),
					Markdown: filepath.Join(workDir, "reports", "demo.md"),
				},
				Targets: []schema.Target{
					{
						ProfileID: profileID,
						Status:    "pass",
						Required:  true,
					},
				},
				Summary: schema.SummaryInfo{Status: "pass"},
			},
		}, nil
	}

	startReq := newValidateMultipartRequest(t, "/api/validate/start", profileID)
	startRec := httptest.NewRecorder()
	s.handleValidateStart(startRec, startReq)
	if startRec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 from validate start, got %d body=%s", startRec.Code, startRec.Body.String())
	}

	var started validateStartResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &started); err != nil {
		t.Fatalf("decode validate start response: %v", err)
	}
	if strings.TrimSpace(started.JobID) == "" {
		t.Fatalf("expected non-empty job_id")
	}

	var final validateStatusResponse
	deadline := time.Now().Add(3 * time.Second)
	for {
		statusReq := httptest.NewRequest(http.MethodGet, "/api/validate/status?job_id="+started.JobID, nil)
		statusRec := httptest.NewRecorder()
		s.handleValidateStatus(statusRec, statusReq)
		if statusRec.Code != http.StatusOK {
			t.Fatalf("expected 200 from validate status, got %d body=%s", statusRec.Code, statusRec.Body.String())
		}
		if err := json.Unmarshal(statusRec.Body.Bytes(), &final); err != nil {
			t.Fatalf("decode validate status response: %v", err)
		}
		if final.State == "completed" || final.State == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for async validation completion; last state=%q payload=%s", final.State, statusRec.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	if final.State != "completed" {
		t.Fatalf("expected completed state, got %q error=%q", final.State, final.Error)
	}
	if final.Percent != 100 {
		t.Fatalf("expected percent=100, got %d", final.Percent)
	}
	if final.Result == nil {
		t.Fatalf("expected final result payload")
	}
	if final.Result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", final.Result.ExitCode)
	}
	if got := final.ProfileStatuses[profileID]; got != "pass" {
		t.Fatalf("expected profile %q to be pass, got %q", profileID, got)
	}
}

func TestValidateStatusEndpointErrors(t *testing.T) {
	// Validate-status is now behind read auth (H-1b). Anonymous validate
	// implies anonymous read of the corresponding status so the async UX
	// still works for the same callers that can submit jobs.
	t.Setenv(envAllowAnonymousValidate, "true")
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	reqMissing := httptest.NewRequest(http.MethodGet, "/api/validate/status", nil)
	recMissing := httptest.NewRecorder()
	s.handleValidateStatus(recMissing, reqMissing)
	if recMissing.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing job id, got %d body=%s", recMissing.Code, recMissing.Body.String())
	}

	reqUnknown := httptest.NewRequest(http.MethodGet, "/api/validate/status?job_id=val-does-not-exist", nil)
	recUnknown := httptest.NewRecorder()
	s.handleValidateStatus(recUnknown, reqUnknown)
	if recUnknown.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown job id, got %d body=%s", recUnknown.Code, recUnknown.Body.String())
	}
}

func newValidateMultipartRequest(t *testing.T, path, profileID string) *http.Request {
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
	if err := writer.WriteField("timeout", "30s"); err != nil {
		t.Fatalf("write timeout: %v", err)
	}
	if err := writer.WriteField("concurrency", "1"); err != nil {
		t.Fatalf("write concurrency: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func firstProfileIDForAsyncValidateTest(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("vm", "profiles", "*.yaml"),
		filepath.Join("..", "..", "vm", "profiles", "*.yaml"),
	}
	var paths []string
	var err error
	for _, pattern := range candidates {
		paths, err = filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob vm profiles (%s): %v", pattern, err)
		}
		if len(paths) > 0 {
			break
		}
	}
	if len(paths) == 0 {
		t.Fatalf("no vm profiles found in known paths")
	}
	sort.Strings(paths)
	base := filepath.Base(paths[0])
	return strings.TrimSuffix(base, filepath.Ext(base))
}
