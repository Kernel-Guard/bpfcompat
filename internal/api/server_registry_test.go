package api

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRegistryAPIProjectAndArtifactFlow(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "bootstrap-token")
	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}

	createProjectBody := `{"tenant":"acme","project":"demo","visibility":"private"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/registry/projects", strings.NewReader(createProjectBody))
	createReq.Header.Set("Authorization", "Bearer bootstrap-token")
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	s.handleRegistryProjects(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create project status=%d body=%s", createRec.Code, createRec.Body.String())
	}

	var uploadBody bytes.Buffer
	writer := multipart.NewWriter(&uploadBody)
	if err := writer.WriteField("tenant", "acme"); err != nil {
		t.Fatalf("tenant field: %v", err)
	}
	if err := writer.WriteField("project", "demo"); err != nil {
		t.Fatalf("project field: %v", err)
	}
	if err := writer.WriteField("artifact_name", "execsnoop"); err != nil {
		t.Fatalf("artifact_name field: %v", err)
	}
	if err := writer.WriteField("artifact_version", "v1"); err != nil {
		t.Fatalf("artifact_version field: %v", err)
	}
	artifactFile, err := writer.CreateFormFile("artifact_file", "execsnoop.bpf.o")
	if err != nil {
		t.Fatalf("create artifact part: %v", err)
	}
	if _, err := artifactFile.Write([]byte("BPF-OBJECT")); err != nil {
		t.Fatalf("write artifact part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	uploadReq := httptest.NewRequest(http.MethodPost, "/api/registry/artifacts/upload", &uploadBody)
	uploadReq.Header.Set("Authorization", "Bearer bootstrap-token")
	uploadReq.Header.Set("Content-Type", writer.FormDataContentType())
	uploadRec := httptest.NewRecorder()
	s.handleRegistryArtifactUpload(uploadRec, uploadReq)
	if uploadRec.Code != http.StatusOK {
		t.Fatalf("upload status=%d body=%s", uploadRec.Code, uploadRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=acme&project=demo&artifact_name=execsnoop&limit=10", nil)
	listReq.Header.Set("Authorization", "Bearer bootstrap-token")
	listRec := httptest.NewRecorder()
	s.handleRegistryArtifacts(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listRec.Code, listRec.Body.String())
	}

	var listPayload struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listPayload.Records) != 1 {
		t.Fatalf("expected one artifact record, got %d", len(listPayload.Records))
	}

	downloadQuery := url.Values{
		"tenant":        []string{"acme"},
		"project":       []string{"demo"},
		"artifact_name": []string{"execsnoop"},
		"version":       []string{"v1"},
	}
	downloadReq := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts/download?"+downloadQuery.Encode(), nil)
	downloadReq.Header.Set("Authorization", "Bearer bootstrap-token")
	downloadRec := httptest.NewRecorder()
	s.handleRegistryArtifactDownload(downloadRec, downloadReq)
	if downloadRec.Code != http.StatusOK {
		t.Fatalf("download status=%d body=%s", downloadRec.Code, downloadRec.Body.String())
	}
	if got := downloadRec.Body.String(); got != "BPF-OBJECT" {
		t.Fatalf("unexpected artifact bytes: %q", got)
	}

	verifyReq := httptest.NewRequest(http.MethodGet, "/api/registry/history/verify?tenant=acme&project=demo", nil)
	verifyReq.Header.Set("Authorization", "Bearer bootstrap-token")
	verifyRec := httptest.NewRecorder()
	s.handleRegistryHistoryVerify(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
}

func TestRegistryAPIRateLimit(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "bootstrap-token")
	t.Setenv(registryRateMaxEnv, "1")
	t.Setenv(registryRateWindowEnv, "60")

	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}
	createProjectBody := `{"tenant":"acme","project":"demo","visibility":"private"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/registry/projects", strings.NewReader(createProjectBody))
	createReq.Header.Set("Authorization", "Bearer bootstrap-token")
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	s.handleRegistryProjects(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create project status=%d body=%s", createRec.Code, createRec.Body.String())
	}

	listReq1 := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=acme&project=demo&artifact_name=execsnoop&limit=10", nil)
	listReq1.Header.Set("Authorization", "Bearer bootstrap-token")
	listRec1 := httptest.NewRecorder()
	s.handleRegistryArtifacts(listRec1, listReq1)
	if listRec1.Code != http.StatusOK {
		t.Fatalf("first list status=%d body=%s", listRec1.Code, listRec1.Body.String())
	}

	listReq2 := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=acme&project=demo&artifact_name=execsnoop&limit=10", nil)
	listReq2.Header.Set("Authorization", "Bearer bootstrap-token")
	listRec2 := httptest.NewRecorder()
	s.handleRegistryArtifacts(listRec2, listReq2)
	if listRec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second list should be rate limited, status=%d body=%s", listRec2.Code, listRec2.Body.String())
	}
}

func TestRegistryProjectUpsertActionScopeDenied(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "bootstrap-token")
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(writeJWTRequiredScopesEnvForAction("registry_project_upsert"), "registry.project.upsert")

	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}

	token := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":   "svc-acme-demo",
		"scope": "api.write",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
	createProjectBody := `{"tenant":"acme","project":"demo","visibility":"private"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/registry/projects", strings.NewReader(createProjectBody))
	createReq.Header.Set("Authorization", "Bearer bootstrap-token")
	createReq.Header.Set(headerIdentityToken, token)
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	s.handleRegistryProjects(createRec, createReq)
	if createRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing registry project upsert scope, got %d body=%s", createRec.Code, createRec.Body.String())
	}
}

func TestRegistryHistoryVerifyActionScopeGate(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "bootstrap-token")
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(writeJWTRequiredScopesEnvForAction("registry_history_verify"), "registry.history.verify")

	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}

	createProjectBody := `{"tenant":"acme","project":"demo","visibility":"private"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/registry/projects", strings.NewReader(createProjectBody))
	createReq.Header.Set("Authorization", "Bearer bootstrap-token")
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	s.handleRegistryProjects(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create project status=%d body=%s", createRec.Code, createRec.Body.String())
	}

	var uploadBody bytes.Buffer
	writer := multipart.NewWriter(&uploadBody)
	if err := writer.WriteField("tenant", "acme"); err != nil {
		t.Fatalf("tenant field: %v", err)
	}
	if err := writer.WriteField("project", "demo"); err != nil {
		t.Fatalf("project field: %v", err)
	}
	if err := writer.WriteField("artifact_name", "execsnoop"); err != nil {
		t.Fatalf("artifact_name field: %v", err)
	}
	if err := writer.WriteField("artifact_version", "v1"); err != nil {
		t.Fatalf("artifact_version field: %v", err)
	}
	artifactFile, err := writer.CreateFormFile("artifact_file", "execsnoop.bpf.o")
	if err != nil {
		t.Fatalf("create artifact part: %v", err)
	}
	if _, err := artifactFile.Write([]byte("BPF-OBJECT")); err != nil {
		t.Fatalf("write artifact part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	uploadReq := httptest.NewRequest(http.MethodPost, "/api/registry/artifacts/upload", &uploadBody)
	uploadReq.Header.Set("Authorization", "Bearer bootstrap-token")
	uploadReq.Header.Set("Content-Type", writer.FormDataContentType())
	uploadRec := httptest.NewRecorder()
	s.handleRegistryArtifactUpload(uploadRec, uploadReq)
	if uploadRec.Code != http.StatusOK {
		t.Fatalf("upload status=%d body=%s", uploadRec.Code, uploadRec.Body.String())
	}

	badIdentity := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":   "svc-acme-demo",
		"scope": "api.write",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
	verifyReqDenied := httptest.NewRequest(http.MethodGet, "/api/registry/history/verify?tenant=acme&project=demo", nil)
	verifyReqDenied.Header.Set("Authorization", "Bearer bootstrap-token")
	verifyReqDenied.Header.Set(headerIdentityToken, badIdentity)
	verifyRecDenied := httptest.NewRecorder()
	s.handleRegistryHistoryVerify(verifyRecDenied, verifyReqDenied)
	if verifyRecDenied.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing registry history verify scope, got %d body=%s", verifyRecDenied.Code, verifyRecDenied.Body.String())
	}

	goodIdentity := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":      "svc-acme-demo",
		"scope":    "registry.history.verify",
		"tenant":   "acme",
		"projects": []string{"demo"},
		"exp":      time.Now().Add(10 * time.Minute).Unix(),
	})
	verifyReqAllowed := httptest.NewRequest(http.MethodGet, "/api/registry/history/verify?tenant=acme&project=demo", nil)
	verifyReqAllowed.Header.Set("Authorization", "Bearer bootstrap-token")
	verifyReqAllowed.Header.Set(headerIdentityToken, goodIdentity)
	verifyRecAllowed := httptest.NewRecorder()
	s.handleRegistryHistoryVerify(verifyRecAllowed, verifyReqAllowed)
	if verifyRecAllowed.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid registry history verify scope, got %d body=%s", verifyRecAllowed.Code, verifyRecAllowed.Body.String())
	}
}

func TestRegistryRequireIdentityDeniedWhenMissingIdentityToken(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "bootstrap-token")
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envRegistryRequireIdentity, "true")

	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}

	req := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=acme&project=demo", nil)
	req.Header.Set("Authorization", "Bearer bootstrap-token")
	rec := httptest.NewRecorder()
	s.handleRegistryArtifacts(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing registry identity token, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "missing write identity token") {
		t.Fatalf("expected missing identity token error, body=%s", rec.Body.String())
	}
}

func TestRegistryRequireIdentityTenantScopeMismatchDenied(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "bootstrap-token")
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envRegistryRequireIdentity, "true")

	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}

	identity := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":    "svc-other",
		"tenant": "other-tenant",
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodGet, "/api/registry/projects?tenant=acme", nil)
	req.Header.Set("Authorization", "Bearer bootstrap-token")
	req.Header.Set(headerIdentityToken, identity)
	rec := httptest.NewRecorder()
	s.handleRegistryProjects(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for tenant scope mismatch, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not authorized for tenant") {
		t.Fatalf("expected tenant authorization denial, body=%s", rec.Body.String())
	}
}
