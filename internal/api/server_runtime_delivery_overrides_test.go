package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/artifact"
	"github.com/kernel-guard/bpfcompat/internal/registry"
)

// runtimeDeliveryOverrideCase is one request body that must be rejected by
// /api/runtime/fetch or /api/runtime/select because it tries to steer the
// server's filesystem access, provenance gate or host probe.
type runtimeDeliveryOverrideCase struct {
	name string
	body string
}

func runtimeFetchOverrideCases(victimRoot, outside string) []runtimeDeliveryOverrideCase {
	return []runtimeDeliveryOverrideCase{
		{"workdir", `{"artifact_name":"victimapp","version":"1.0.0","workdir":` + jsonString(victimRoot) + `}`},
		{"out_dir", `{"artifact_name":"victimapp","version":"1.0.0","out_dir":` + jsonString(outside) + `}`},
		{"require_verified_history_false", `{"artifact_name":"victimapp","version":"1.0.0","require_verified_history":false}`},
		{"probe_use_sudo", `{"artifact_name":"victimapp","probe":{"use_sudo":false}}`},
		{"probe_sudo_non_interactive", `{"artifact_name":"victimapp","probe":{"sudo_non_interactive":false}}`},
		{"cross_tenant_combined", `{"artifact_name":"victimapp","version":"1.0.0","workdir":` + jsonString(victimRoot) + `,"out_dir":` + jsonString(outside) + `,"require_verified_history":false}`},
	}
}

func runtimeSelectOverrideCases(victimRoot string) []runtimeDeliveryOverrideCase {
	return []runtimeDeliveryOverrideCase{
		{"workdir", `{"artifact_name":"victimapp","workdir":` + jsonString(victimRoot) + `}`},
		{"probe_use_sudo", `{"artifact_name":"victimapp","probe":{"use_sudo":false}}`},
		{"probe_sudo_non_interactive", `{"artifact_name":"victimapp","probe":{"sudo_non_interactive":false}}`},
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

type runtimeDeliveryAuthMode struct {
	name  string
	setup func(t *testing.T)
	apply func(r *http.Request)
}

func runtimeDeliveryAuthModes() []runtimeDeliveryAuthMode {
	return []runtimeDeliveryAuthMode{
		{
			name: "anonymous",
			setup: func(t *testing.T) {
				t.Setenv(envAllowAnonymousRuntimeDelivery, "true")
				t.Setenv(envWriteAPIKey, "")
			},
			apply: func(*http.Request) {},
		},
		{
			name: "authenticated",
			setup: func(t *testing.T) {
				t.Setenv(envAllowAnonymousRuntimeDelivery, "false")
				t.Setenv(envAllowAnonymousWrite, "false")
				t.Setenv(envWriteAPIKey, "delivery-write-key")
			},
			apply: func(r *http.Request) { r.Header.Set(headerAPIKey, "delivery-write-key") },
		},
	}
}

func assertNoPathEcho(t *testing.T, body string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if p != "" && strings.Contains(body, p) {
			t.Fatalf("error body echoes a caller-supplied path: %s", body)
		}
	}
}

// TestRuntimeFetchRejectsRequestOverrides covers RS-1: fetch must not let a
// caller choose the registry it reads (cross-tenant), the directory it writes
// into, disable history verification, or steer the sudo host probe.
func TestRuntimeFetchRejectsRequestOverrides(t *testing.T) {
	for _, mode := range runtimeDeliveryAuthModes() {
		srvWork := t.TempDir()
		seedRuntimeExecuteProjectArtifact(t, srvWork, "victim", "secretproj", "victimapp", "1.0.0")
		victimRoot := registryProjectWorkDir(srvWork, "victim", "secretproj")
		// Also seed the server's own registry so that every override case
		// would otherwise succeed and the 400 is attributable to the guard.
		seedServerLocalArtifact(t, srvWork, "victimapp", "1.0.0")
		outsideBase := t.TempDir()
		outside := filepath.Join(outsideBase, mode.name, "attacker", "dir")
		for _, tc := range runtimeFetchOverrideCases(victimRoot, outside) {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				mode.setup(t)
				s := &Server{cfg: Config{WorkDir: srvWork}}
				req := httptest.NewRequest(http.MethodPost, "/api/runtime/fetch", strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
				mode.apply(req)
				rec := httptest.NewRecorder()
				s.handleRuntimeFetch(rec, req)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
				}
				if !strings.Contains(rec.Body.String(), "for API runtime ") {
					t.Fatalf("expected the override guard to reject the request, body=%s", rec.Body.String())
				}
				assertNoPathEcho(t, rec.Body.String(), victimRoot, outsideBase)
				if _, err := os.Stat(filepath.Join(outsideBase, mode.name)); !os.IsNotExist(err) {
					t.Fatalf("fetch created a directory outside the server workdir (stat err=%v)", err)
				}
				if _, err := os.Stat(filepath.Join(victimRoot, defaultRuntimeFetchDir)); !os.IsNotExist(err) {
					t.Fatalf("fetch wrote into the victim tenant tree (stat err=%v)", err)
				}
				if _, err := os.Stat(filepath.Join(srvWork, defaultRuntimeFetchDir)); !os.IsNotExist(err) {
					t.Fatalf("rejected fetch must not write anything (stat err=%v)", err)
				}
			})
		}
	}
}

// TestRuntimeSelectRejectsRequestOverrides covers RS-1 for select: the caller
// must not choose which registry (for example another tenant's) is read.
func TestRuntimeSelectRejectsRequestOverrides(t *testing.T) {
	for _, mode := range runtimeDeliveryAuthModes() {
		srvWork := t.TempDir()
		seedRuntimeExecuteProjectArtifact(t, srvWork, "victim", "secretproj", "victimapp", "1.0.0")
		victimRoot := registryProjectWorkDir(srvWork, "victim", "secretproj")
		// Also seed the server's own registry so that every override case
		// would otherwise succeed and the 400 is attributable to the guard.
		seedServerLocalArtifact(t, srvWork, "victimapp", "1.0.0")
		for _, tc := range runtimeSelectOverrideCases(victimRoot) {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				mode.setup(t)
				s := &Server{cfg: Config{WorkDir: srvWork}}
				req := httptest.NewRequest(http.MethodPost, "/api/runtime/select", strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
				mode.apply(req)
				rec := httptest.NewRecorder()
				s.handleRuntimeSelect(rec, req)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
				}
				if !strings.Contains(rec.Body.String(), "for API runtime ") {
					t.Fatalf("expected the override guard to reject the request, body=%s", rec.Body.String())
				}
				assertNoPathEcho(t, rec.Body.String(), victimRoot)
				if strings.Contains(rec.Body.String(), "selection") {
					t.Fatalf("select returned a selection for an override request: %s", rec.Body.String())
				}
			})
		}
	}
}

// seedServerLocalArtifact persists a fetchable artifact into the server's own
// (non-tenant) local registry, which is what fetch/select read.
func seedServerLocalArtifact(t *testing.T, workDir, name, version string) {
	t.Helper()
	srcPath := filepath.Join(t.TempDir(), name+".bpf.o")
	if err := os.WriteFile(srcPath, []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01}, 0o644); err != nil {
		t.Fatalf("write source artifact: %v", err)
	}
	meta, err := artifact.Inspect(srcPath)
	if err != nil {
		t.Fatalf("inspect source artifact: %v", err)
	}
	if err := registry.PersistArtifactVersion(workDir, registry.ArtifactVersionRecord{
		ArtifactName:      name,
		ArtifactVersion:   version,
		ArtifactPath:      srcPath,
		ArtifactSHA256:    meta.SHA256,
		RunID:             "seed-run-" + version,
		JSONReportPath:    filepath.Join(workDir, "runs", "seed-run-"+version, "report.json"),
		SummaryStatus:     "pass",
		RequiredPassed:    1,
		TotalProfiles:     1,
		SupportedProfiles: []string{"ubuntu-24.04-6.8"},
	}); err != nil {
		t.Fatalf("persist artifact version: %v", err)
	}
}

// TestRuntimeFetchWithoutOverridesUsesServerWorkdir is the positive control:
// a fetch without overrides still works, keeps the verified-history gate, and
// lands under the server's configured workdir.
func TestRuntimeFetchWithoutOverridesUsesServerWorkdir(t *testing.T) {
	t.Setenv(envAllowAnonymousRuntimeDelivery, "true")
	t.Setenv(envWriteAPIKey, "")
	srvWork := t.TempDir()
	seedServerLocalArtifact(t, srvWork, "demoapp", "1.0.0")
	s := &Server{cfg: Config{WorkDir: srvWork}}

	// require_verified_history:true is the default and stays accepted.
	body := `{"artifact_name":"demoapp","version":"1.0.0","require_verified_history":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/fetch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRuntimeFetch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for fetch without overrides, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "history_verification") {
		t.Fatalf("expected history verification in response: %s", rec.Body.String())
	}
	entries, err := os.ReadDir(filepath.Join(srvWork, defaultRuntimeFetchDir))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one fetched file under server workdir, entries=%v err=%v", entries, err)
	}
}

// TestRuntimeSelectWithoutOverridesIsNotRejected checks that select requests
// without overrides (including the prefer_privileged probe flag execute also
// accepts) are not caught by the override guard.
func TestRuntimeSelectWithoutOverridesIsNotRejected(t *testing.T) {
	t.Setenv(envAllowAnonymousRuntimeDelivery, "true")
	t.Setenv(envWriteAPIKey, "")
	srvWork := t.TempDir()
	seedServerLocalArtifact(t, srvWork, "demoapp", "1.0.0")
	s := &Server{cfg: Config{WorkDir: srvWork}}

	body := `{"artifact_name":"demoapp","probe":{"prefer_privileged":false}}`
	req := httptest.NewRequest(http.MethodPost, "/api/runtime/select", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleRuntimeSelect(rec, req)
	if strings.Contains(rec.Body.String(), "for API runtime ") {
		t.Fatalf("select without overrides was rejected as an override: %d %s", rec.Code, rec.Body.String())
	}
	t.Logf("select status=%d", rec.Code)
}
