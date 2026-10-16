package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/runtime"
)

// SIGN-4: the API execute path must hand the worker the verified digest so
// the worker re-hashes the exact bytes it gives the validator.
func TestRuntimeExecutePassesVerifiedSHA256ToWorker(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Cleanup(func() {
		_ = os.RemoveAll("artifacts")
	})
	workDir := t.TempDir()
	seedRuntimeExecuteProjectArtifactForSecurityTest(t, workDir, "acme", "demo", "simple_pass", "v1")
	sum := sha256.Sum256([]byte("BPF-OBJECT-BYTES"))
	want := hex.EncodeToString(sum[:])

	t.Setenv(envAllowRuntimeExec, "true")
	t.Setenv(envWriteAPIKey, "demo-write-key")
	t.Setenv(envRuntimeExecApprove, "approve-token")
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "registry-bootstrap")

	originalWorkerFn := runRuntimeExecuteWorkerFn
	t.Cleanup(func() { runRuntimeExecuteWorkerFn = originalWorkerFn })
	var got runtime.ExecuteRequest
	runRuntimeExecuteWorkerFn = func(ctx context.Context, req runtime.ExecuteRequest) (runtime.ExecuteResult, error) {
		got = req
		return runtime.ExecuteResult{SchemaVersion: "runtime_execute.v0.1", Status: "pass"}, nil
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
	if got.ExpectedSHA256 != want {
		t.Fatalf("worker ExpectedSHA256=%q, want verified record sha %q", got.ExpectedSHA256, want)
	}

	wantRoot := filepath.Join(workDir, defaultRuntimeFetchDir)
	if got.ArtifactRoot != wantRoot {
		t.Fatalf("worker ArtifactRoot=%q, want server-controlled fetch dir %q", got.ArtifactRoot, wantRoot)
	}
	if !strings.HasPrefix(got.ArtifactPath, wantRoot+string(filepath.Separator)) {
		t.Fatalf("worker ArtifactPath=%q not under ArtifactRoot %q", got.ArtifactPath, wantRoot)
	}

	// The digest and root must survive the worker stdin protocol.
	raw, err := json.Marshal(runtime.ExecuteWorkerRequest{Execute: got})
	if err != nil {
		t.Fatal(err)
	}
	var decoded runtime.ExecuteWorkerRequest
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Execute.ExpectedSHA256 != want || decoded.Execute.ArtifactRoot != wantRoot {
		t.Fatalf("worker protocol dropped ExpectedSHA256: %s", raw)
	}
}
