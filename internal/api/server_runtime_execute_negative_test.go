package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/erenari/bpfcompat/internal/cloudregistry"
)

func TestRuntimeExecuteCrossTenantTokenDenied(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	workDir := t.TempDir()
	seedRuntimeExecuteProjectArtifact(t, workDir, "acme", "demo", "simple_pass", "v1")
	writeRegistryAuthConfig(t, workDir, cloudregistry.AuthConfig{
		Tokens: []cloudregistry.TokenGrant{
			{
				Token:    "other-tenant-token",
				Subject:  "other-tenant-writer",
				Tenant:   "otherco",
				Projects: []string{"*"},
				CanRead:  true,
				CanWrite: true,
			},
		},
	})

	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")

	s := &Server{cfg: Config{WorkDir: workDir}}
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{
		"tenant":"acme",
		"project":"demo",
		"artifact_name":"simple_pass",
		"version":"v1",
		"allow_host_load":true
	}`))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set(headerExecApprove, "approve-token")
	req.Header.Set("Authorization", "Bearer other-tenant-token")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-tenant token, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRuntimeExecuteTamperedHistoryFailsBeforeHostLoad(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	workDir := t.TempDir()
	seedRuntimeExecuteProjectArtifact(t, workDir, "acme", "demo", "simple_pass", "v1")
	tamperProjectHistoryRecord(t, workDir, "acme", "demo", func(record map[string]any) {
		record["record_sha256"] = "deadbeef"
	})

	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "registry-bootstrap")

	s := &Server{cfg: Config{WorkDir: workDir}}
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{
		"tenant":"acme",
		"project":"demo",
		"artifact_name":"simple_pass",
		"version":"v1",
		"allow_host_load":true
	}`))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set(headerExecApprove, "approve-token")
	req.Header.Set("Authorization", "Bearer registry-bootstrap")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 for tampered history, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "history verification failed") {
		t.Fatalf("expected history verification failure, body=%s", rec.Body.String())
	}
}

func TestRuntimeExecuteUnsignedHistoryFailsBeforeHostLoad(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	workDir := t.TempDir()
	seedRuntimeExecuteProjectArtifact(t, workDir, "acme", "demo", "simple_pass", "v1")
	tamperProjectHistoryRecord(t, workDir, "acme", "demo", func(record map[string]any) {
		record["signature"] = ""
		record["signature_alg"] = ""
		record["signature_key_id"] = ""
		record["signature_public_key"] = ""
	})

	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "registry-bootstrap")

	s := &Server{cfg: Config{WorkDir: workDir}}
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{
		"tenant":"acme",
		"project":"demo",
		"artifact_name":"simple_pass",
		"version":"v1",
		"allow_host_load":true
	}`))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set(headerExecApprove, "approve-token")
	req.Header.Set("Authorization", "Bearer registry-bootstrap")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 for unsigned history, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "history verification failed") {
		t.Fatalf("expected history verification failure, body=%s", rec.Body.String())
	}
}

func seedRuntimeExecuteProjectArtifact(t *testing.T, workDir, tenant, project, artifactName, version string) {
	t.Helper()
	store := cloudregistry.NewStore(workDir)
	if _, err := store.UpsertProject(cloudregistry.CreateProjectInput{
		Tenant:     tenant,
		Project:    project,
		Visibility: "private",
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	if _, err := store.UploadArtifact(cloudregistry.UploadInput{
		Tenant:          tenant,
		Project:         project,
		ArtifactName:    artifactName,
		ArtifactVersion: version,
		ArtifactReader:  strings.NewReader("BPF-OBJECT-BYTES"),
		SourceRunID:     "seed-run-" + version,
		Compatibility: cloudregistry.CompatibilityMetadata{
			SummaryStatus:     "pass",
			RequiredPassed:    1,
			RequiredFailed:    0,
			TotalProfiles:     1,
			SupportedProfiles: []string{"ubuntu-24.04-6.8"},
		},
	}); err != nil {
		t.Fatalf("upload artifact: %v", err)
	}
}

func writeRegistryAuthConfig(t *testing.T, workDir string, cfg cloudregistry.AuthConfig) {
	t.Helper()
	path := filepath.Join(workDir, "cloud-registry", "auth", "tokens.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create auth config directory: %v", err)
	}
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal auth config: %v", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write auth config: %v", err)
	}
}

func tamperProjectHistoryRecord(
	t *testing.T,
	workDir string,
	tenant string,
	project string,
	mutate func(record map[string]any),
) {
	t.Helper()
	path := filepath.Join(
		workDir,
		"cloud-registry",
		"tenants",
		tenant,
		"projects",
		project,
		"registry",
		"artifact_versions.jsonl",
	)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read project history: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 {
		t.Fatalf("expected at least one history line in %s", path)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("decode project history line: %v", err)
	}
	mutate(record)
	line, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("encode tampered project history line: %v", err)
	}
	lines[0] = string(line)
	out := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatalf("write tampered project history: %v", err)
	}
}
