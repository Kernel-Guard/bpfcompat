package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/erenari/bpfcompat/internal/cloudregistry"
	"github.com/erenari/bpfcompat/internal/runtime"
)

func TestWriteEndpointRequiresConfiguredAPIKey(t *testing.T) {
	t.Setenv(envWriteAPIKey, "")
	s := &Server{}

	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	s.handleCompare(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when write key is missing, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWriteEndpointRejectsMissingOrInvalidKey(t *testing.T) {
	t.Setenv(envWriteAPIKey, "demo-write-key")
	s := &Server{}

	reqMissing := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	recMissing := httptest.NewRecorder()
	s.handleCompare(recMissing, reqMissing)
	if recMissing.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing write key, got %d body=%s", recMissing.Code, recMissing.Body.String())
	}

	reqValid := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	reqValid.Header.Set("X-API-Key", "demo-write-key")
	recValid := httptest.NewRecorder()
	s.handleCompare(recValid, reqValid)
	if recValid.Code == http.StatusUnauthorized || recValid.Code == http.StatusServiceUnavailable {
		t.Fatalf("expected request to pass auth, got %d body=%s", recValid.Code, recValid.Body.String())
	}
}

func TestWriteEndpointCompareActionScopeDenied(t *testing.T) {
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envWriteRequireIdentity, "true")
	t.Setenv(writeJWTRequiredScopesEnvForAction("compare"), "compare.run")
	s := &Server{}

	token := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":   "svc-acme-demo",
		"scope": "api.write",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(`{}`))
	req.Header.Set(headerIdentityToken, token)
	rec := httptest.NewRecorder()
	s.handleCompare(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing compare action scope, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "compare scopes") {
		t.Fatalf("expected compare scope denial message, body=%s", rec.Body.String())
	}
}

func TestRuntimeExecuteDisabledByDefault(t *testing.T) {
	t.Setenv(envAllowRuntimeExec, "")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	s := &Server{}

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{"artifact_name":"simple_pass","allow_host_load":true}`))
	req.Header.Set("X-API-Key", "demo-write-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when runtime execute is disabled, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRuntimeExecuteRequiresApprovalTokenConfigAndHeader(t *testing.T) {
	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "")
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{"tenant":"acme","project":"demo","artifact_name":"simple_pass","allow_host_load":true}`))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when approval token env is missing, got %d body=%s", rec.Code, rec.Body.String())
	}

	t.Setenv(envRuntimeExecApprove, "approve-token")
	reqBad := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{"tenant":"acme","project":"demo","artifact_name":"simple_pass","allow_host_load":true}`))
	reqBad.Header.Set(headerAPIKey, "demo-write-key")
	reqBad.Header.Set(headerExecApprove, "wrong-token")
	reqBad.Header.Set("Content-Type", "application/json")
	recBad := httptest.NewRecorder()
	s.handleRuntimeExecute(recBad, reqBad)
	if recBad.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for invalid approval token, got %d body=%s", recBad.Code, recBad.Body.String())
	}
}

func TestRuntimeExecuteKillSwitchBlocksAndAudits(t *testing.T) {
	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv(envRuntimeExecKill, "true")
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "registry-bootstrap")

	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{"tenant":"acme","project":"demo","artifact_name":"simple_pass","allow_host_load":true}`))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set("Authorization", "Bearer registry-bootstrap")
	req.Header.Set(headerExecApprove, "approve-token")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when kill switch is enabled, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "kill switch") {
		t.Fatalf("expected kill switch message, got body=%s", rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode kill-switch response payload: %v", err)
	}
	correlationID, _ := payload["correlation_id"].(string)
	if correlationID == "" {
		t.Fatalf("expected correlation_id in kill-switch response")
	}

	events, err := runtime.ListDecisionEvents(workDir, 1)
	if err != nil {
		t.Fatalf("list runtime decision events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected exactly one runtime decision event, got %d", len(events))
	}
	if events[0].Status != "denied" {
		t.Fatalf("expected denied runtime decision status, got %q", events[0].Status)
	}
	if events[0].Operation != "execute" {
		t.Fatalf("expected execute operation, got %q", events[0].Operation)
	}
	if events[0].ArtifactName != "simple_pass" {
		t.Fatalf("expected artifact_name=simple_pass, got %q", events[0].ArtifactName)
	}
	if events[0].DecisionID != correlationID {
		t.Fatalf("expected runtime decision id to match correlation id, got decision_id=%q correlation_id=%q", events[0].DecisionID, correlationID)
	}

	store := cloudregistry.NewStore(workDir)
	auditEvents, err := store.ListAuditEvents("acme", "demo", 20)
	if err != nil {
		t.Fatalf("list cloud registry audit events: %v", err)
	}
	audit := findAuditEventByAction(auditEvents, "runtime_execute_denied")
	if audit == nil {
		t.Fatalf("expected runtime_execute_denied audit event")
	}
	if audit.Metadata == nil {
		t.Fatalf("expected metadata on runtime_execute_denied audit event")
	}
	if got := metadataString(audit.Metadata, "correlation_id"); got != correlationID {
		t.Fatalf("expected correlation_id=%q in audit metadata, got %q", correlationID, got)
	}
	if got := metadataString(audit.Metadata, "approved_by"); got == "" {
		t.Fatalf("expected approved_by in audit metadata")
	}
	if got := metadataString(audit.Metadata, "requested_by"); got == "" {
		t.Fatalf("expected requested_by in audit metadata")
	}
}

func TestRuntimeExecuteRequiresTenantProject(t *testing.T) {
	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{"artifact_name":"simple_pass","allow_host_load":true}`))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set(headerExecApprove, "approve-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing tenant/project, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRuntimeExecuteRequiresRegistryAuthorization(t *testing.T) {
	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{"tenant":"acme","project":"demo","artifact_name":"simple_pass","allow_host_load":true}`))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set(headerExecApprove, "approve-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing registry auth token, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRuntimeExecuteRejectsRequestOverrides(t *testing.T) {
	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{
		"tenant":"acme",
		"project":"demo",
		"artifact_name":"simple_pass",
		"allow_host_load":true,
		"out_dir":"custom/out"
	}`))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set(headerExecApprove, "approve-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for out_dir override, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRuntimeExecuteUsesWorkerBoundary(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Cleanup(func() {
		_ = os.RemoveAll("artifacts")
	})
	workDir := t.TempDir()
	seedRuntimeExecuteProjectArtifactForSecurityTest(t, workDir, "acme", "demo", "simple_pass", "v1")

	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "registry-bootstrap")

	originalWorkerFn := runRuntimeExecuteWorkerFn
	defer func() { runRuntimeExecuteWorkerFn = originalWorkerFn }()

	workerCalled := false
	runRuntimeExecuteWorkerFn = func(ctx context.Context, req runtime.ExecuteRequest) (runtime.ExecuteResult, error) {
		workerCalled = true
		return runtime.ExecuteResult{
			SchemaVersion: "runtime_execute.v0.1",
			Status:        "pass",
			ArtifactPath:  req.ArtifactPath,
			AttachMode:    req.AttachMode,
			ProbeFeatures: req.ProbeFeatures,
			UsedSudo:      req.UseSudo,
			ExitCode:      0,
		}, nil
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
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !workerCalled {
		t.Fatalf("expected runtime execute worker function to be called")
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	execObj, ok := payload["execution"].(map[string]any)
	if !ok {
		t.Fatalf("expected execution object in response")
	}
	if got := execObj["status"]; got != "pass" {
		t.Fatalf("expected execution.status=pass, got=%v", got)
	}
	correlationID, _ := payload["correlation_id"].(string)
	if correlationID == "" {
		t.Fatalf("expected correlation_id in runtime execute success response")
	}
	auditObj, ok := payload["audit"].(map[string]any)
	if !ok {
		t.Fatalf("expected audit object in runtime execute success response")
	}
	decisionID, _ := auditObj["decision_id"].(string)
	if decisionID == "" {
		t.Fatalf("expected decision_id in runtime execute success audit payload")
	}
	if decisionID != correlationID {
		t.Fatalf("expected response correlation_id to equal audit decision_id, got correlation_id=%q decision_id=%q", correlationID, decisionID)
	}

	store := cloudregistry.NewStore(workDir)
	events, err := store.ListAuditEvents("acme", "demo", 20)
	if err != nil {
		t.Fatalf("list cloud registry audit events: %v", err)
	}
	audit := findAuditEventByAction(events, "runtime_execute")
	if audit == nil {
		t.Fatalf("expected runtime_execute success audit event")
	}
	if audit.Metadata == nil {
		t.Fatalf("expected runtime_execute audit metadata")
	}
	if got := metadataString(audit.Metadata, "correlation_id"); got != correlationID {
		t.Fatalf("expected correlation_id=%q in runtime_execute audit metadata, got %q", correlationID, got)
	}
	if got := metadataString(audit.Metadata, "execution_status"); got != "pass" {
		t.Fatalf("expected execution_status=pass in runtime_execute audit metadata, got %q", got)
	}
	if got := metadataString(audit.Metadata, "artifact_sha256"); got == "" {
		t.Fatalf("expected artifact_sha256 in runtime_execute audit metadata")
	}
}

func TestRuntimeExecuteRequiresWorkerIdentityWhenEnabled(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	workDir := t.TempDir()
	seedRuntimeExecuteProjectArtifactForSecurityTest(t, workDir, "acme", "demo", "simple_pass", "v1")

	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv(envRuntimeExecRequireWorkerIdentity, "true")
	t.Setenv(envRuntimeExecWorkerUser, "")
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
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when worker identity is required but missing, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), envRuntimeExecWorkerUser) {
		t.Fatalf("expected response to mention %s, body=%s", envRuntimeExecWorkerUser, rec.Body.String())
	}
}

func TestRuntimeExecuteIdentityScopeDenied(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	workDir := t.TempDir()
	seedRuntimeExecuteProjectArtifactForSecurityTest(t, workDir, "acme", "demo", "simple_pass", "v1")

	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envWriteRequireIdentity, "true")
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "registry-bootstrap")

	identityToken := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":      "svc-acme-demo",
		"tenant":   "acme",
		"projects": []string{"other-project"},
		"exp":      time.Now().Add(10 * time.Minute).Unix(),
	})

	s := &Server{cfg: Config{WorkDir: workDir}}
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{
		"tenant":"acme",
		"project":"demo",
		"artifact_name":"simple_pass",
		"version":"v1",
		"allow_host_load":true
	}`))
	req.Header.Set(headerIdentityToken, identityToken)
	req.Header.Set(headerExecApprove, "approve-token")
	req.Header.Set("Authorization", "Bearer registry-bootstrap")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for identity scope mismatch, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not authorized for project") {
		t.Fatalf("expected identity scope denial message, body=%s", rec.Body.String())
	}
}

func TestRuntimeExecuteSupportsIdentityJWTWithoutAPIKey(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	workDir := t.TempDir()
	seedRuntimeExecuteProjectArtifactForSecurityTest(t, workDir, "acme", "demo", "simple_pass", "v1")

	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envWriteRequireIdentity, "true")
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "registry-bootstrap")

	identityToken := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":      "svc-acme-demo",
		"tenant":   "acme",
		"projects": []string{"demo"},
		"exp":      time.Now().Add(10 * time.Minute).Unix(),
	})

	originalWorkerFn := runRuntimeExecuteWorkerFn
	defer func() { runRuntimeExecuteWorkerFn = originalWorkerFn }()
	runRuntimeExecuteWorkerFn = func(ctx context.Context, req runtime.ExecuteRequest) (runtime.ExecuteResult, error) {
		return runtime.ExecuteResult{
			SchemaVersion: "runtime_execute.v0.1",
			Status:        "pass",
			ArtifactPath:  req.ArtifactPath,
			ExitCode:      0,
		}, nil
	}

	s := &Server{cfg: Config{WorkDir: workDir}}
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{
		"tenant":"acme",
		"project":"demo",
		"artifact_name":"simple_pass",
		"version":"v1",
		"allow_host_load":true
	}`))
	req.Header.Set(headerIdentityToken, identityToken)
	req.Header.Set(headerExecApprove, "approve-token")
	req.Header.Set("Authorization", "Bearer registry-bootstrap")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for identity JWT runtime execute, got %d body=%s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	correlationID, _ := payload["correlation_id"].(string)
	if correlationID == "" {
		t.Fatalf("expected correlation_id in response")
	}

	store := cloudregistry.NewStore(workDir)
	events, err := store.ListAuditEvents("acme", "demo", 20)
	if err != nil {
		t.Fatalf("list cloud registry audit events: %v", err)
	}
	audit := findAuditEventByAction(events, "runtime_execute")
	if audit == nil {
		t.Fatalf("expected runtime_execute audit event")
	}
	if got := metadataString(audit.Metadata, "requested_by"); got != "svc-acme-demo" {
		t.Fatalf("expected requested_by=svc-acme-demo, got %q", got)
	}
	if got := metadataString(audit.Metadata, "correlation_id"); got != correlationID {
		t.Fatalf("expected correlation_id=%q, got %q", correlationID, got)
	}
}

func TestRuntimeExecuteIdentityMissingRuntimeScopeDenied(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	workDir := t.TempDir()
	seedRuntimeExecuteProjectArtifactForSecurityTest(t, workDir, "acme", "demo", "simple_pass", "v1")

	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envWriteRequireIdentity, "true")
	t.Setenv(envRuntimeExecJWTRequiredScopes, "runtime.execute")
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "registry-bootstrap")

	identityToken := mustHS256JWT(t, "identity-secret", map[string]any{
		"sub":   "svc-acme-demo",
		"scope": "api.write",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})

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
	req.Header.Set(headerIdentityToken, identityToken)
	req.Header.Set(headerExecApprove, "approve-token")
	req.Header.Set("Authorization", "Bearer registry-bootstrap")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	s.handleRuntimeExecute(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing runtime.execute scope, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "runtime execute scopes") {
		t.Fatalf("expected runtime execute scope denial message, body=%s", rec.Body.String())
	}
	if workerCalled {
		t.Fatalf("runtime execute worker should not be called when runtime scope is missing")
	}
}

func TestRuntimeExecuteWorkerCommand(t *testing.T) {
	name, args := runtimeExecuteWorkerCommand("/opt/bpfcompat/bin/bpfcompat", "")
	if name != "/opt/bpfcompat/bin/bpfcompat" {
		t.Fatalf("unexpected direct worker command name: %q", name)
	}
	if len(args) != 2 || args[0] != "runtime" || args[1] != "worker-execute" {
		t.Fatalf("unexpected direct worker args: %v", args)
	}

	sudoName, sudoArgs := runtimeExecuteWorkerCommand("/opt/bpfcompat/bin/bpfcompat", "bpfcompat-worker")
	if sudoName != "sudo" {
		t.Fatalf("expected sudo command, got %q", sudoName)
	}
	// "--" sits between sudo's own flags and the command-to-execute so a
	// pathological worker binary path beginning with "-" can't be parsed as
	// another sudo option (M-3).
	want := []string{"-n", "-u", "bpfcompat-worker", "--", "/opt/bpfcompat/bin/bpfcompat", "runtime", "worker-execute"}
	if strings.Join(sudoArgs, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected sudo args: got=%v want=%v", sudoArgs, want)
	}
}

func seedRuntimeExecuteProjectArtifactForSecurityTest(t *testing.T, workDir, tenant, project, artifactName, version string) {
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

func findAuditEventByAction(events []cloudregistry.AuditEvent, action string) *cloudregistry.AuditEvent {
	for i := range events {
		if strings.TrimSpace(events[i].Action) == action {
			return &events[i]
		}
	}
	return nil
}

func metadataString(metadata map[string]any, key string) string {
	value, ok := metadata[key]
	if !ok || value == nil {
		return ""
	}
	out, _ := value.(string)
	return strings.TrimSpace(out)
}

func mustHS256JWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerRaw, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal jwt header: %v", err)
	}
	claimsRaw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal jwt claims: %v", err)
	}
	headerPart := base64.RawURLEncoding.EncodeToString(headerRaw)
	claimsPart := base64.RawURLEncoding.EncodeToString(claimsRaw)
	signingInput := headerPart + "." + claimsPart
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(signingInput)); err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	signaturePart := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", signingInput, signaturePart)
}

func TestWithSecurityHeaders(t *testing.T) {
	handler := withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), false)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected X-Frame-Options=DENY, got %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options=nosniff, got %q", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatalf("expected Content-Security-Policy header")
	}
	// SECURITY: HSTS must only appear when TLS is actually in use; serving
	// HSTS over plain HTTP would mislead any client that respects the header.
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("expected no Strict-Transport-Security without TLS, got %q", got)
	}

	tlsHandler := withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), true)
	tlsRec := httptest.NewRecorder()
	tlsHandler.ServeHTTP(tlsRec, req)
	if got := tlsRec.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatalf("expected Strict-Transport-Security when TLS is enabled")
	}
}

func TestAPIConfigEndpoint(t *testing.T) {
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envWriteJWTSecret, "identity-secret")
	t.Setenv(envWriteRequireIdentity, "true")
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(envAllowAnonymousWrite, "true")
	t.Setenv(envAllowAnonymousRuntimeDelivery, "true")
	t.Setenv(envRegistryRequireIdentity, "true")
	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envRuntimeExecKill, "true")
	t.Setenv(envRuntimeExecApprove, "approve-token")

	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	rec := httptest.NewRecorder()
	s.handleConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var cfg apiConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode config response: %v", err)
	}
	if !cfg.WriteAPIKeyConfigured {
		t.Fatalf("expected write_api_key_configured=true")
	}
	if !cfg.WriteIdentityVerifierEnabled {
		t.Fatalf("expected write_identity_verifier_enabled=true")
	}
	if !cfg.WriteRequireIdentity {
		t.Fatalf("expected write_require_identity=true")
	}
	if !cfg.AllowAnonymousValidate {
		t.Fatalf("expected allow_anonymous_validate=true")
	}
	if !cfg.AllowAnonymousWrite {
		t.Fatalf("expected allow_anonymous_write=true")
	}
	if !cfg.AllowAnonymousRuntimeDelivery {
		t.Fatalf("expected allow_anonymous_runtime_delivery=true")
	}
	if !cfg.RegistryRequireIdentity {
		t.Fatalf("expected registry_require_identity=true")
	}
	if !cfg.RuntimeExecuteEnabled {
		t.Fatalf("expected runtime_execute_enabled=true")
	}
	if !cfg.RuntimeExecuteKillSwitch {
		t.Fatalf("expected runtime_execute_kill_switch=true")
	}
	if !cfg.RuntimeExecuteApprovalConfig {
		t.Fatalf("expected runtime_execute_approval_configured=true")
	}
}

func TestRuntimeSanitizationHelpers(t *testing.T) {
	probe := runtimeProbeFixture()
	sanitizedProbe := sanitizeHostProbeForAPI(probe)
	if sanitizedProbe.Host.Hostname != "demo-host" {
		t.Fatalf("expected host redaction, got %q", sanitizedProbe.Host.Hostname)
	}

	execResult := runtimeExecuteFixture()
	sanitizedExec := sanitizeExecuteResultForAPI(execResult)
	if strings.Contains(sanitizedExec.ArtifactPath, "/home/") {
		t.Fatalf("expected artifact path to be redacted, got %q", sanitizedExec.ArtifactPath)
	}
	if sanitizedExec.Stderr != "" {
		t.Fatalf("expected stderr to be redacted")
	}
	for _, arg := range sanitizedExec.Command {
		if strings.Contains(arg, "/home/") {
			t.Fatalf("expected command args to be redacted, got %q", arg)
		}
	}
}

func runtimeProbeFixture() runtime.HostCapabilities {
	var probe runtime.HostCapabilities
	probe.Host.Hostname = "bpfcompat-host24"
	probe.Host.Arch = "amd64"
	return probe
}

func runtimeExecuteFixture() runtime.ExecuteResult {
	return runtime.ExecuteResult{
		ArtifactPath:        "/home/azureuser/bpfcompat/artifacts/runtime-selected/simple_pass.o",
		ManifestPath:        "/home/azureuser/bpfcompat/examples/simple-pass/manifest.yaml",
		RunDir:              ".bpfcompat/runtime-runs/abc",
		LogDir:              ".bpfcompat/runtime-runs/abc/logs",
		ValidatorResultPath: ".bpfcompat/runtime-runs/abc/result.json",
		StderrPath:          ".bpfcompat/runtime-runs/abc/stderr.log",
		Stderr:              "sensitive stderr path /home/azureuser",
		Command:             []string{"sudo", "-n", "/home/azureuser/bpfcompat/validator/c-libbpf/bin/bpfcompat-validator"},
	}
}

// TestSanitizeFileNameRejectsShellMetachars regresses C-1. Filenames carrying
// shell metacharacters used to flow straight into the qemu/SSH validator
// command string and let a crafted upload run arbitrary commands inside the
// guest VM. After tightening, anything that doesn't fit the strict allowlist
// collapses to the supplied fallback.
func TestSanitizeFileNameRejectsShellMetachars(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		expect string
	}{
		{"backticks", "evil`whoami`.bpf.o", "fallback.bpf.o"},
		{"semicolon", "evil; rm -rf ~.bpf.o", "fallback.bpf.o"},
		{"dollar paren", "evil$(id).bpf.o", "fallback.bpf.o"},
		{"newline", "evil.bpf.o\nrm -rf /", "fallback.bpf.o"},
		{"space", "evil file.bpf.o", "fallback.bpf.o"},
		{"dotdot", "../escape.bpf.o", "escape.bpf.o"},
		{"clean", "demo-artifact.bpf.o", "demo-artifact.bpf.o"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeFileName(tc.input, "fallback.bpf.o")
			if got != tc.expect {
				t.Fatalf("sanitizeFileName(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

// TestShortIDIsRandom regresses H-1a. The previous timestamp-based ID was
// monotonically increasing and trivially enumerable; combined with the
// unauthenticated /api/validate/status endpoint that let attackers scrape
// other tenants' results. After the fix shortID returns 16 random bytes
// hex-encoded.
func TestShortIDIsRandom(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 64; i++ {
		id := shortID()
		if len(id) != 32 {
			t.Fatalf("shortID returned unexpected length %d (%q)", len(id), id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("shortID returned duplicate %q within %d iterations", id, i)
		}
		seen[id] = struct{}{}
	}
}

// TestReadEndpointsRejectUnauthenticated regresses H-1b. Before the fix any
// reachable client could enumerate validate results, history, runtime probe,
// and runtime decisions without credentials.
func TestReadEndpointsRejectUnauthenticated(t *testing.T) {
	t.Setenv(envWriteAPIKey, "")
	t.Setenv(envAllowAnonymousWrite, "")
	t.Setenv(envAllowAnonymousRead, "")
	t.Setenv(envAllowAnonymousValidate, "")

	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}

	cases := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		url     string
	}{
		{"validate_status", s.handleValidateStatus, "/api/validate/status?job_id=val-x"},
		{"history_artifacts", s.handleHistoryArtifacts, "/api/history/artifacts"},
		{"history_runs", s.handleHistoryRuns, "/api/history/runs"},
		{"run_report", s.handleRunReport, "/api/history/run-report?run_id=demo"},
		{"runtime_probe", s.handleRuntimeProbe, "/api/runtime/probe"},
		{"runtime_decisions", s.handleRuntimeDecisions, "/api/runtime/decisions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code == http.StatusOK {
				t.Fatalf("expected non-200 for unauthenticated %s, got 200 body=%s", tc.name, rec.Body.String())
			}
			if rec.Code == http.StatusBadRequest {
				t.Fatalf("auth check should run before parameter validation for %s, got 400 body=%s", tc.name, rec.Body.String())
			}
		})
	}
}

// TestReadEndpointsAllowAuthenticated confirms that supplying the configured
// API key restores access to the read surface after H-1b's auth gate.
func TestReadEndpointsAllowAuthenticated(t *testing.T) {
	t.Setenv(envWriteAPIKey, "read-key")

	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}
	req := httptest.NewRequest(http.MethodGet, "/api/history/artifacts", nil)
	req.Header.Set(headerAPIKey, "read-key")
	rec := httptest.NewRecorder()
	s.handleHistoryArtifacts(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated history, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestRedactErrorMessage regresses M-4. Failure responses used to leak the
// absolute paths embedded in raw err.Error() strings; the redactor swaps
// absolute paths for "[redacted]/<basename>" while leaving the rest of the
// message alone.
func TestRedactErrorMessage(t *testing.T) {
	t.Setenv(envRedactRuntime, "true")
	got := redactErrorMessage("runtime fetch failed: open /home/op/.bpfcompat/runs/abc/artifact: no such file")
	if strings.Contains(got, "/home/op") {
		t.Fatalf("expected /home/op to be redacted, got %q", got)
	}
	if !strings.Contains(got, "[redacted]/artifact") {
		t.Fatalf("expected redacted basename hint, got %q", got)
	}

	t.Setenv(envRedactRuntime, "false")
	raw := redactErrorMessage("open /home/op/path: denied")
	if !strings.Contains(raw, "/home/op/path") {
		t.Fatalf("redaction should pass through when disabled, got %q", raw)
	}
}

// TestEnforceWriteIdentityTenantProjectRequiresScopeClaim regresses M-2. The
// previous behaviour returned nil when the JWT carried neither tenant nor
// projects, which let bare {sub, exp, can_write} tokens authorize every
// tenant/project pair.
func TestEnforceWriteIdentityTenantProjectRequiresScopeClaim(t *testing.T) {
	bare := writeAuthIdentity{Subject: "anyone", AuthType: "jwt"}
	if err := enforceWriteIdentityTenantProject(bare, "acme", "demo"); err == nil {
		t.Fatalf("expected enforceWriteIdentityTenantProject to reject bare JWT with no tenant/projects")
	}

	scoped := writeAuthIdentity{Subject: "svc", AuthType: "jwt", Tenant: "acme", Projects: []string{"demo"}}
	if err := enforceWriteIdentityTenantProject(scoped, "acme", "demo"); err != nil {
		t.Fatalf("expected explicit scope to pass: %v", err)
	}

	// Tenant-only flow is still gated.
	tenantOnlyMissing := writeAuthIdentity{Subject: "svc", AuthType: "jwt"}
	if err := enforceWriteIdentityTenant(tenantOnlyMissing, "acme"); err == nil {
		t.Fatalf("expected enforceWriteIdentityTenant to reject JWT with no tenant claim")
	}
}

// TestServerTLSConfig regresses M-1. tlsEnabled flips when both cert/key are
// set so the server picks ListenAndServeTLS and the HSTS header gets emitted.
func TestServerTLSConfig(t *testing.T) {
	s := &Server{cfg: Config{TLSCertPath: "/tmp/cert.pem", TLSKeyPath: "/tmp/key.pem"}}
	if !s.tlsEnabled() {
		t.Fatalf("expected tlsEnabled when both cert and key are set")
	}
	partial := &Server{cfg: Config{TLSCertPath: "/tmp/cert.pem"}}
	if partial.tlsEnabled() {
		t.Fatalf("expected tlsEnabled=false when only cert is set")
	}
	none := &Server{cfg: Config{}}
	if none.tlsEnabled() {
		t.Fatalf("expected tlsEnabled=false when no TLS material is supplied")
	}
}
