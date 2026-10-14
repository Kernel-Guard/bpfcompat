package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeProbeTools puts fake `sudo` and `bpftool` executables first on
// PATH. The fake sudo records its argv (one invocation per line) and fails, so
// the probe falls back to the fake unprivileged bpftool. It returns the path
// of the sudo argv log.
func installFakeProbeTools(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the sudo probe path is only taken when the server is not root")
	}
	binDir := t.TempDir()
	sudoLog := filepath.Join(t.TempDir(), "sudo-argv.log")
	sudoScript := "#!/bin/sh\necho \"$*\" >> '" + sudoLog + "'\nexit 1\n"
	bpftoolScript := "#!/bin/sh\necho 'eBPF program_type tracepoint is available'\n"
	if err := os.WriteFile(filepath.Join(binDir, "sudo"), []byte(sudoScript), 0o755); err != nil {
		t.Fatalf("write fake sudo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "bpftool"), []byte(bpftoolScript), 0o755); err != nil {
		t.Fatalf("write fake bpftool: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return sudoLog
}

func readSudoInvocations(t *testing.T, sudoLog string) []string {
	t.Helper()
	raw, err := os.ReadFile(sudoLog)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read sudo log: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// TestRuntimeProbeRejectsInteractiveSudo: GET /api/runtime/probe must never
// make the server run sudo without -n. sudo_non_interactive=false is rejected
// with the shared fixed-message 400 before any probe command runs.
func TestRuntimeProbeRejectsInteractiveSudo(t *testing.T) {
	t.Setenv(envAllowAnonymousRead, "true")
	sudoLog := installFakeProbeTools(t)
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	for _, query := range []string{
		"prefer_privileged=true&sudo_non_interactive=false",
		"prefer_privileged=true&use_sudo=true&sudo_non_interactive=0",
		"sudo_non_interactive=FALSE",
	} {
		t.Run(query, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/runtime/probe?"+query, http.NoBody)
			rec := httptest.NewRecorder()
			s.handleRuntimeProbe(rec, req)
			if got := readSudoInvocations(t, sudoLog); len(got) != 0 {
				t.Fatalf("sudo must not run for this probe request, got invocations %q", got)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "probe sudo overrides are not allowed for API runtime probe") {
				t.Fatalf("expected the shared override guard message, body=%s", rec.Body.String())
			}
		})
	}
}

// TestRuntimeProbePrivilegedSudoIsNonInteractive: the accepted forms
// (sudo_non_interactive omitted or true) always invoke sudo with -n, and the
// same holds for the probe object of POST /api/runtime/select.
func TestRuntimeProbePrivilegedSudoIsNonInteractive(t *testing.T) {
	t.Setenv(envAllowAnonymousRead, "true")
	t.Setenv(envAllowAnonymousRuntimeDelivery, "true")
	t.Setenv(envWriteAPIKey, "")

	cases := []struct {
		name string
		run  func(s *Server) *httptest.ResponseRecorder
	}{
		{"probe_default", func(s *Server) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			s.handleRuntimeProbe(rec, httptest.NewRequest(http.MethodGet, "/api/runtime/probe?prefer_privileged=true", http.NoBody))
			return rec
		}},
		{"probe_explicit_true", func(s *Server) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			s.handleRuntimeProbe(rec, httptest.NewRequest(http.MethodGet, "/api/runtime/probe?prefer_privileged=true&sudo_non_interactive=true", http.NoBody))
			return rec
		}},
		{"select_probe_object", func(s *Server) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/runtime/select", strings.NewReader(`{"artifact_name":"demoapp","probe":{"prefer_privileged":true}}`))
			req.Header.Set("Content-Type", "application/json")
			s.handleRuntimeSelect(rec, req)
			return rec
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sudoLog := installFakeProbeTools(t)
			s := &Server{cfg: Config{WorkDir: t.TempDir()}}
			rec := tc.run(s)
			if rec.Code == http.StatusInternalServerError {
				t.Fatalf("probe failed: %s", rec.Body.String())
			}
			got := readSudoInvocations(t, sudoLog)
			if len(got) == 0 {
				t.Fatalf("expected the privileged probe to try sudo, body=%s", rec.Body.String())
			}
			for _, argv := range got {
				if !strings.HasPrefix(argv, "-n -- ") {
					t.Fatalf("sudo must run non-interactively (-n), got argv %q", argv)
				}
			}
		})
	}
}
