package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/runtime"
)

func seedDecisionTrace(t *testing.T, workDir, artifactName string) {
	t.Helper()
	if _, err := runtime.PersistDecisionTrace(workDir, runtime.DecisionTrace{
		Source:       "api",
		Operation:    "fetch",
		ArtifactName: artifactName,
		Status:       "success",
	}); err != nil {
		t.Fatalf("persist decision trace: %v", err)
	}
}

func runtimeDecisionsReadAuthModes() []runtimeDeliveryAuthMode {
	return []runtimeDeliveryAuthMode{
		{
			name: "anonymous",
			setup: func(t *testing.T) {
				t.Setenv(envAllowAnonymousRead, "true")
				t.Setenv(envWriteAPIKey, "")
			},
			apply: func(*http.Request) {},
		},
		{
			name: "authenticated",
			setup: func(t *testing.T) {
				t.Setenv(envAllowAnonymousRead, "false")
				t.Setenv(envAllowAnonymousWrite, "false")
				t.Setenv(envWriteAPIKey, "decisions-read-key")
			},
			apply: func(r *http.Request) { r.Header.Set(headerAPIKey, "decisions-read-key") },
		},
	}
}

// TestRuntimeDecisionsRejectsWorkdirOverride: GET /api/runtime/decisions must
// not read decision history from a caller-chosen directory (another tenant's
// tree or anywhere else on the host).
func TestRuntimeDecisionsRejectsWorkdirOverride(t *testing.T) {
	srvWork := t.TempDir()
	victimRoot := registryProjectWorkDir(srvWork, "victim", "secretproj")
	seedDecisionTrace(t, victimRoot, "victimsecretapp")
	arbitrary := t.TempDir()
	seedDecisionTrace(t, arbitrary, "arbitrarysecretapp")

	targets := map[string]string{"cross_tenant": victimRoot, "arbitrary_dir": arbitrary}
	for _, mode := range runtimeDecisionsReadAuthModes() {
		for name, target := range targets {
			t.Run(mode.name+"/"+name, func(t *testing.T) {
				mode.setup(t)
				s := &Server{cfg: Config{WorkDir: srvWork}}
				req := httptest.NewRequest(http.MethodGet, "/api/runtime/decisions?workdir="+url.QueryEscape(target), http.NoBody)
				mode.apply(req)
				rec := httptest.NewRecorder()
				s.handleRuntimeDecisions(rec, req)
				body := rec.Body.String()
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("expected 400, got %d body=%s", rec.Code, body)
				}
				if !strings.Contains(body, "workdir override is not allowed for API runtime decisions") {
					t.Fatalf("expected the shared override guard message, body=%s", body)
				}
				assertNoPathEcho(t, body, target, srvWork)
				if strings.Contains(body, "secretapp") {
					t.Fatalf("decisions leaked records from outside the server workdir: %s", body)
				}
			})
		}
	}
}

// TestRuntimeDecisionsWithoutOverrideReadsServerWorkdir is the positive
// control: no override reads the server's own decision history only.
func TestRuntimeDecisionsWithoutOverrideReadsServerWorkdir(t *testing.T) {
	t.Setenv(envAllowAnonymousRead, "true")
	srvWork := t.TempDir()
	seedDecisionTrace(t, srvWork, "serverownapp")
	seedDecisionTrace(t, registryProjectWorkDir(srvWork, "victim", "secretproj"), "victimsecretapp")
	s := &Server{cfg: Config{WorkDir: srvWork}}

	req := httptest.NewRequest(http.MethodGet, "/api/runtime/decisions?limit=10", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleRuntimeDecisions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "serverownapp") {
		t.Fatalf("expected the server's own decision record, body=%s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "victimsecretapp") {
		t.Fatalf("decisions returned a tenant-scoped record: %s", rec.Body.String())
	}
}
