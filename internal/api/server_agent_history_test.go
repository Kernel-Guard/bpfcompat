package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/cloudregistry"
)

func seedAgentDecisionProject(t *testing.T) string {
	t.Helper()
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "bootstrap-token")
	workDir := t.TempDir()
	store := cloudregistry.NewStore(workDir)
	if _, err := store.UpsertProject(cloudregistry.CreateProjectInput{Tenant: "acme", Project: "demo", Visibility: "private"}); err != nil {
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
			TotalProfiles:     1,
			SupportedProfiles: []string{"ubuntu-22.04-5.15"},
		},
	}); err != nil {
		t.Fatalf("upload artifact: %v", err)
	}
	return workDir
}

func postAgentDecision(s *Server, extra string) *httptest.ResponseRecorder {
	body := `{"tenant":"acme","project":"demo","agent_id":"host-1","artifact_name":"aegis",` + extra +
		`"host_probe":{"schema_version":"runtime_probe.v0.1","os":{"id":"ubuntu","version_id":"22.04"},"kernel":{"release":"5.15.0-100-generic"},"btf":{"kernel_available":true}}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/decision", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer bootstrap-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleAgentDecision(rec, req)
	return rec
}

// TestAgentDecisionRejectsUnverifiedHistory: like runtime fetch/execute, the
// agent decision endpoint must not let a caller (even a token-authenticated
// one) switch off signed artifact-history verification.
func TestAgentDecisionRejectsUnverifiedHistory(t *testing.T) {
	s := &Server{cfg: Config{WorkDir: seedAgentDecisionProject(t)}}
	rec := postAgentDecision(s, `"require_verified_history":false,`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "require_verified_history must be true for API runtime agent decision") {
		t.Fatalf("expected the shared override guard message, body=%s", rec.Body.String())
	}
}

// TestAgentDecisionVerifiesHistoryByDefault: omitted and explicit true are
// accepted and the decision carries a verified history result.
func TestAgentDecisionVerifiesHistoryByDefault(t *testing.T) {
	for name, extra := range map[string]string{"omitted": ``, "explicit_true": `"require_verified_history":true,`} {
		t.Run(name, func(t *testing.T) {
			s := &Server{cfg: Config{WorkDir: seedAgentDecisionProject(t)}}
			rec := postAgentDecision(s, extra)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
			}
			var payload struct {
				Decision struct {
					HistoryVerification *struct {
						Verified bool `json:"verified"`
					} `json:"history_verification"`
				} `json:"decision"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload.Decision.HistoryVerification == nil || !payload.Decision.HistoryVerification.Verified {
				t.Fatalf("expected verified history in the decision, body=%s", rec.Body.String())
			}
		})
	}
}
