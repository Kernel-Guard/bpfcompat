package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/erenari/bpfcompat/internal/cloudregistry"
)

func TestAgentDecisionSelectsProjectArtifact(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "bootstrap-token")
	workDir := t.TempDir()
	store := cloudregistry.NewStore(workDir)
	if _, err := store.UpsertProject(cloudregistry.CreateProjectInput{
		Tenant:     "acme",
		Project:    "demo",
		Visibility: "private",
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	if _, err := store.UploadArtifact(cloudregistry.UploadInput{
		Tenant:          "acme",
		Project:         "demo",
		ArtifactName:    "aegis",
		ArtifactVersion: "v1",
		ArtifactReader:  bytes.NewReader([]byte("BPF-OBJECT")),
		Compatibility: cloudregistry.CompatibilityMetadata{
			SummaryStatus:     "pass",
			RequiredPassed:    1,
			RequiredFailed:    0,
			TotalProfiles:     1,
			SupportedProfiles: []string{"ubuntu-22.04-5.15"},
		},
	}); err != nil {
		t.Fatalf("upload artifact: %v", err)
	}

	body := `{
		"tenant":"acme",
		"project":"demo",
		"agent_id":"host-1",
		"artifact_name":"aegis",
		"host_probe":{
			"schema_version":"runtime_probe.v0.1",
			"os":{"id":"ubuntu","version_id":"22.04"},
			"kernel":{"release":"5.15.0-100-generic"},
			"btf":{"kernel_available":true}
		},
		"policy":{"require_summary_pass":true,"max_required_failed":0}
	}`
	s := &Server{cfg: Config{WorkDir: workDir}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/decision", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer bootstrap-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleAgentDecision(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("agent decision status=%d body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Decision struct {
			SelectedArtifact struct {
				Name        string `json:"name"`
				Version     string `json:"version"`
				DownloadURL string `json:"download_url"`
			} `json:"selected_artifact"`
			LoadApproved bool `json:"load_approved"`
		} `json:"decision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Decision.SelectedArtifact.Name != "aegis" || payload.Decision.SelectedArtifact.Version != "v1" {
		t.Fatalf("unexpected selected artifact: %+v", payload.Decision.SelectedArtifact)
	}
	if !strings.Contains(payload.Decision.SelectedArtifact.DownloadURL, "/api/v1/registry/artifacts/download?") {
		t.Fatalf("expected registry download URL, got %q", payload.Decision.SelectedArtifact.DownloadURL)
	}
	if payload.Decision.LoadApproved {
		t.Fatalf("agent decision endpoint must not approve host load")
	}
}

func TestAgentDecisionRequiresRegistryAuth(t *testing.T) {
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "bootstrap-token")
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/decision", strings.NewReader(`{
		"tenant":"acme",
		"project":"demo",
		"artifact_name":"aegis",
		"host_probe":{"schema_version":"runtime_probe.v0.1"}
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleAgentDecision(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}
