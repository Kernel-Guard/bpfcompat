package api

import (
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// spillTestPartBytes is a file part well above maxMultipartFormBytes but
// well below the default upload body cap.
const spillTestPartBytes = 16 << 20

// uploadEntryPoint is one HTTP handler that parses a multipart upload.
type uploadEntryPoint struct {
	name   string
	path   string
	handle func(*Server, http.ResponseWriter, *http.Request)
	extra  map[string]string
}

// uploadEntryPoints enumerates EVERY handler that calls parseUploadForm.
// Each request is built to be rejected after the form is parsed (registry:
// no token -> 401; validate: invalid timeout -> 400) so no runner is
// reached.
func uploadEntryPoints(t *testing.T) []uploadEntryPoint {
	t.Helper()
	profileID := firstProfileIDForAsyncValidateTest(t)
	validateExtra := map[string]string{"profiles": profileID, "timeout": "not-a-duration"}
	return []uploadEntryPoint{
		{"registry_upload", "/api/registry/artifacts/upload", (*Server).handleRegistryArtifactUpload,
			map[string]string{"tenant": "t", "project": "p", "artifact_name": "a", "artifact_version": "1"}},
		{"validate_sync", "/api/validate", (*Server).handleValidate, validateExtra},
		{"validate_start", "/api/validate/start", (*Server).handleValidateStart, validateExtra},
	}
}

func multipartTempFiles(t *testing.T, dir string) []string {
	t.Helper()
	left, err := filepath.Glob(filepath.Join(dir, "multipart-*"))
	if err != nil {
		t.Fatalf("glob temp dir: %v", err)
	}
	return left
}

// TestUploadLargeFilePartSpillsToDiskAndIsRemoved: a file part larger than
// maxMultipartFormBytes must be spilled to a temp file (not held in the
// heap), and the handler must remove that temp file itself before it
// returns. After the handler returns, opening the part must therefore fail
// with ErrNotExist: an in-memory part would open fine, and a leaked temp
// file would open as an *os.File.
func TestUploadLargeFilePartSpillsToDiskAndIsRemoved(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	for _, ep := range uploadEntryPoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			s, workDir := newUploadTestServer(t)
			s.runValidate = runnerMustNotRun(t)

			req := streamingValidateRequest(ep.path, spillTestPartBytes, ep.extra)
			rec := httptest.NewRecorder()
			ep.handle(s, rec, req)
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected the request to be rejected after parsing (400/401), got %d body=%s", rec.Code, rec.Body.String())
			}
			if req.MultipartForm == nil || len(req.MultipartForm.File["artifact_file"]) != 1 {
				t.Fatalf("expected the handler to have parsed one artifact_file part")
			}
			fh := req.MultipartForm.File["artifact_file"][0]
			if fh.Size != spillTestPartBytes {
				t.Fatalf("artifact_file size = %d, want %d", fh.Size, spillTestPartBytes)
			}
			f, err := fh.Open()
			switch {
			case err == nil:
				_, onDisk := f.(*os.File)
				_ = f.Close()
				if onDisk {
					t.Fatalf("%d-byte part was spilled to disk but its temp file was not removed by the handler", fh.Size)
				}
				t.Fatalf("%d-byte part was held in memory (maxMultipartFormBytes=%d); it must spill to a temp file", fh.Size, maxMultipartFormBytes)
			case !errors.Is(err, fs.ErrNotExist):
				t.Fatalf("open parsed part: unexpected error %v", err)
			}
			if left := multipartTempFiles(t, tmp); len(left) > 0 {
				t.Fatalf("multipart temp files left behind: %v", left)
			}
			assertNoUploads(t, workDir)
		})
	}
}

// TestUploadSpilledPartsRemovedBehindRequestLogging drives every upload
// entry point through a real HTTP server behind withRequestLogging. That
// middleware calls r.WithContext, so the handler parses the form on a
// shallow copy of the request and net/http's own end-of-request
// MultipartForm.RemoveAll (which only sees the original request) never
// runs: the handler has to remove the spilled temp files itself.
func TestUploadSpilledPartsRemovedBehindRequestLogging(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, ep := range uploadEntryPoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			s, _ := newUploadTestServer(t)
			s.runValidate = runnerMustNotRun(t)
			handle := ep.handle
			ts := httptest.NewServer(withRequestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handle(s, w, r)
			}), logger))
			defer ts.Close()

			req := streamingValidateRequest(ep.path, spillTestPartBytes, ep.extra)
			resp, err := http.Post(ts.URL+ep.path, req.Header.Get("Content-Type"), req.Body)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("expected 400/401, got %d", resp.StatusCode)
			}
			// The handler may still be unwinding its defers after the
			// response reached the client; give it a bounded moment.
			deadline := time.Now().Add(3 * time.Second)
			for {
				left := multipartTempFiles(t, tmp)
				if len(left) == 0 {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("multipart temp files leaked after the request completed: %v", left)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

// TestUploadFormLargeTextFieldsStillAccepted: non-file fields are held in
// memory and Go budgets them at maxMemory+10 MiB. A 12 MiB text field
// (larger than maxMultipartFormBytes) must still parse, so pasted
// source_code / manifest_text / report_json keep working well beyond any
// realistic size.
func TestUploadFormLargeTextFieldsStillAccepted(t *testing.T) {
	body, contentType := multipartTextFieldBody(t, "source_code", 12<<20)
	req := httptest.NewRequest(http.MethodPost, "/api/validate", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	status, err := parseUploadForm(rec, req)
	if err != nil {
		t.Fatalf("parseUploadForm: status=%d err=%v", status, err)
	}
	defer func() { _ = req.MultipartForm.RemoveAll() }()
	if got := len(req.MultipartForm.Value["source_code"][0]); got != 12<<20 {
		t.Fatalf("source_code length = %d, want %d", got, 12<<20)
	}
}

// TestUploadFormOversizedTextFieldsRejectedWith413: text fields beyond the
// in-memory budget are a size problem, not a malformed request.
func TestUploadFormOversizedTextFieldsRejectedWith413(t *testing.T) {
	body, contentType := multipartTextFieldBody(t, "source_code", maxMultipartFormBytes+(11<<20))
	req := httptest.NewRequest(http.MethodPost, "/api/validate", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	status, err := parseUploadForm(rec, req)
	if err == nil {
		_ = req.MultipartForm.RemoveAll()
		t.Fatalf("expected oversized text fields to be rejected")
	}
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d (%v), want 413", status, err)
	}
}

func multipartTextFieldBody(t *testing.T, name string, size int) (io.Reader, string) {
	t.Helper()
	var sb strings.Builder
	mw := multipart.NewWriter(&sb)
	if err := mw.WriteField(name, strings.Repeat("x", size)); err != nil {
		t.Fatalf("write field: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return strings.NewReader(sb.String()), mw.FormDataContentType()
}
