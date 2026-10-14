package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func postCompareWithBodies(t *testing.T, baseBody, headBody string) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv(envWriteAPIKey, "demo-write-key")
	root := t.TempDir()
	chdirTo(t, root)
	workDir := filepath.Join(root, ".bpfcompat")
	reports := filepath.Join(root, "reports")
	for _, d := range []string{workDir, reports} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	basePath := filepath.Join(reports, "base.json")
	headPath := filepath.Join(reports, "head.json")
	if err := os.WriteFile(basePath, []byte(baseBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(headPath, []byte(headBody), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{WorkDir: workDir}}
	body := `{"base_report":"` + basePath + `","head_report":"` + headPath + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(body))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleCompare(rec, req)
	return rec
}

func assertInvalidReport400(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an invalid report, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), invalidCompareReportMessage) {
		t.Fatalf("expected the fixed invalid-report message, got %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "reports") || strings.Contains(rec.Body.String(), ".json") {
		t.Fatalf("response echoed a report path: %s", rec.Body.String())
	}
}

func TestHandleCompareRejectsDuplicateProfileIDs(t *testing.T) {
	dup := `{"schema_version":"v0.1","targets":[` +
		`{"profile_id":"p","required":true,"status":"fail"},` +
		`{"profile_id":"p","required":true,"status":"pass"}]}`
	assertInvalidReport400(t, postCompareWithBodies(t, sampleReportJSON, dup))
}
