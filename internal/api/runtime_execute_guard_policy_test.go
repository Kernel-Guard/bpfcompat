package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/erenari/bpfcompat/internal/manifest"
	"github.com/erenari/bpfcompat/internal/registry"
	"github.com/erenari/bpfcompat/internal/runtime"
)

func TestLoadRuntimeExecuteGuardPolicyFromEnvJSON(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "runtime-exec-policy.json")
	raw := `{
  "schema_version": "runtime_execute_policy.v0.1",
  "default_action": "deny",
  "rules": [
    {
      "name": "allow-acme-demo",
      "action": "allow",
      "tenants": ["acme"],
      "projects": ["demo"],
      "artifacts": ["simple_pass"],
      "profiles": ["ubuntu-24.04-6.8"]
    }
  ]
}`
	if err := os.WriteFile(policyPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	t.Setenv(envRuntimeExecPolicyPath, policyPath)
	policy, err := loadRuntimeExecuteGuardPolicyFromEnv()
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if policy == nil {
		t.Fatalf("expected policy to be loaded")
	}
	if policy.DefaultAction != "deny" {
		t.Fatalf("expected default_action=deny, got %q", policy.DefaultAction)
	}
	if len(policy.Rules) != 1 {
		t.Fatalf("expected one policy rule, got %d", len(policy.Rules))
	}
	if policy.Rules[0].Name != "allow-acme-demo" {
		t.Fatalf("unexpected rule name: %q", policy.Rules[0].Name)
	}
}

func TestLoadRuntimeExecuteGuardPolicyRejectsUnknownFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string
		raw  string
	}{
		{
			name: "yaml",
			file: "runtime-exec-policy.yaml",
			raw: `schema_version: runtime_execute_policy.v0.1
default_actions: deny
rules: []
`,
		},
		{
			name: "json",
			file: "runtime-exec-policy.json",
			raw: `{
  "schema_version": "runtime_execute_policy.v0.1",
  "default_actions": "deny",
  "rules": []
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policyPath := filepath.Join(t.TempDir(), tc.file)
			if err := os.WriteFile(policyPath, []byte(tc.raw), 0o644); err != nil {
				t.Fatalf("write policy file: %v", err)
			}
			t.Setenv(envRuntimeExecPolicyPath, policyPath)

			_, err := loadRuntimeExecuteGuardPolicyFromEnv()
			if err == nil {
				t.Fatalf("expected unknown policy field to be rejected")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "unknown") && !strings.Contains(strings.ToLower(err.Error()), "field") {
				t.Fatalf("expected unknown-field parse error, got %v", err)
			}
		})
	}
}

func TestRuntimeExecutePolicyRequiredWithoutPath(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv(envRuntimeExecRequirePolicy, "true")
	t.Setenv(envRuntimeExecPolicyPath, "")
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "registry-bootstrap")

	s := &Server{cfg: Config{WorkDir: t.TempDir()}}
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
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when policy is required and missing, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), envRuntimeExecPolicyPath) {
		t.Fatalf("expected policy path hint in body=%s", rec.Body.String())
	}
}

func TestRuntimeExecutePolicyDenyByArtifact(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	workDir := t.TempDir()
	seedRuntimeExecuteProjectArtifact(t, workDir, "acme", "demo", "simple_pass", "v1")

	policyPath := filepath.Join(workDir, "runtime-exec-policy.json")
	raw := `{
  "schema_version": "runtime_execute_policy.v0.1",
  "default_action": "allow",
  "rules": [
    {
      "name": "deny-simple-pass",
      "action": "deny",
      "tenants": ["acme"],
      "projects": ["demo"],
      "artifacts": ["simple_pass"]
    }
  ]
}`
	if err := os.WriteFile(policyPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv(envRuntimeExecPolicyPath, policyPath)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "registry-bootstrap")

	originalWorkerFn := runRuntimeExecuteWorkerFn
	defer func() { runRuntimeExecuteWorkerFn = originalWorkerFn }()
	workerCalled := false
	runRuntimeExecuteWorkerFn = func(ctx context.Context, req runtime.ExecuteRequest) (runtime.ExecuteResult, error) {
		workerCalled = true
		return runtime.ExecuteResult{Status: "pass"}, nil
	}

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
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for deny policy rule, got %d body=%s", rec.Code, rec.Body.String())
	}
	if workerCalled {
		t.Fatalf("worker should not be called when policy denies execution")
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response payload: %v", err)
	}
	policyObj, ok := payload["policy"].(map[string]any)
	if !ok {
		t.Fatalf("expected policy object in deny response")
	}
	if got := policyObj["rule"]; got != "deny-simple-pass" {
		t.Fatalf("expected deny rule deny-simple-pass, got %v", got)
	}
}

func TestEvaluateRuntimeExecuteGuardPolicyKernelManifestHistory(t *testing.T) {
	requireVerified := true
	policy := runtimeExecuteGuardPolicy{
		DefaultAction: "deny",
		Rules: []runtimeExecuteGuardRule{
			{
				Name:                   "allow-kernel-manifest",
				Action:                 "allow",
				Tenants:                []string{"acme"},
				Projects:               []string{"demo"},
				Artifacts:              []string{"execsnoop"},
				Profiles:               []string{"ubuntu-24.04-6.8"},
				ProgramTypes:           []string{"TRACING"},
				AttachKinds:            []string{"TRACEPOINT"},
				KernelMin:              "6.8.0",
				KernelMax:              "6.8.99",
				RequireVerifiedHistory: &requireVerified,
			},
		},
	}
	if err := policy.normalizeAndValidate(); err != nil {
		t.Fatalf("normalize policy: %v", err)
	}

	hostProbe := runtime.HostCapabilities{}
	hostProbe.Kernel.Release = "6.8.0-31-generic"
	ctx := runtimeExecuteGuardContext{
		Tenant:          "acme",
		Project:         "demo",
		ArtifactName:    "execsnoop",
		TargetProfileID: "ubuntu-24.04-6.8",
		SelectedRecord: registry.ArtifactVersionRecord{
			SupportedProfiles: []string{"ubuntu-24.04-6.8"},
		},
		HostProbe:       &hostProbe,
		HistoryVerified: true,
		Manifest: &manifest.Manifest{
			Name: "execsnoop",
			Programs: []manifest.Program{
				{
					Name: "main",
					Type: "tracing",
					Attach: manifest.Attach{
						Kind: "tracepoint",
					},
				},
			},
		},
	}

	decision := evaluateRuntimeExecuteGuardPolicy(policy, ctx)
	if !decision.Allowed {
		t.Fatalf("expected policy allow decision, got %+v", decision)
	}
	if decision.RuleName != "allow-kernel-manifest" {
		t.Fatalf("unexpected rule name: %q", decision.RuleName)
	}
}
