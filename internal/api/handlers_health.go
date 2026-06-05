package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/erenari/bpfcompat/internal/version"
)

// Health-style endpoints. /api/health is the legacy lightweight check;
// /livez and /readyz are the Kubernetes-conformant probes. The split is
// deliberate: livez never fails (a failed liveness causes a restart and we
// want crash-only semantics there), readyz reflects whether dependencies
// the API needs are reachable.

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleLivez is the Kubernetes-style liveness probe. It returns 200 as long
// as the process is running and can serve HTTP at all. Anything that should
// trigger a pod restart (deadlocked goroutine, blown heap) belongs here, but
// the bar is deliberately low because liveness failures cause a restart.
// Crashes already manifest as TCP refusal; liveness only catches "process
// alive but wedged".
func (s *Server) handleLivez(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// handleReadyz signals "ready to take traffic". This is where dependencies
// get checked: the configured workdir must exist and be writable (artifact
// staging, audit log, registry state all live there), and we surface any
// known startup failure mode the operator should see.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	checks := s.readinessChecks()
	overall := http.StatusOK
	for _, c := range checks {
		if !c.OK {
			overall = http.StatusServiceUnavailable
			break
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(overall)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  http.StatusText(overall),
		"checks":  checks,
		"version": version.Resolve().Version,
	})
}

// readinessCheck is the shape published on /readyz so operators can see
// exactly which probe gated traffic. Keep names short and machine-friendly;
// dashboards often graph these directly.
type readinessCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// readinessChecks runs cheap, side-effect-free probes that gate readiness.
// We deliberately avoid hitting external dependencies (JWKS URL, cloud
// registry storage) so a failing dependency doesn't take us out of rotation
// — those should be tracked via Prometheus alerts, not k8s readiness.
func (s *Server) readinessChecks() []readinessCheck {
	checks := []readinessCheck{}

	workDir := strings.TrimSpace(s.cfg.WorkDir)
	if workDir == "" {
		workDir = ".bpfcompat"
	}
	cleanWorkDir := filepath.Clean(workDir)
	if err := os.MkdirAll(cleanWorkDir, 0o755); err != nil {
		checks = append(checks, readinessCheck{
			Name:    "workdir",
			OK:      false,
			Message: "cannot create workdir: " + err.Error(),
		})
	} else {
		// Probe writability by creating then removing a sentinel file.
		// This catches the common "ConfigMap mounted RO over the workdir"
		// failure mode early instead of failing on the first POST.
		probe := filepath.Join(cleanWorkDir, ".readyz-probe")
		if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
			checks = append(checks, readinessCheck{
				Name:    "workdir",
				OK:      false,
				Message: "workdir not writable: " + err.Error(),
			})
		} else {
			_ = os.Remove(probe)
			checks = append(checks, readinessCheck{Name: "workdir", OK: true})
		}
	}

	// If TLS is configured the cert/key must exist and be readable. Missing
	// material means we never managed to start ListenAndServeTLS, so failing
	// readiness lets a rolling deploy back the bad pod out before traffic.
	if s.tlsEnabled() {
		certOK := true
		for _, p := range []string{s.cfg.TLSCertPath, s.cfg.TLSKeyPath} {
			if _, err := os.Stat(filepath.Clean(p)); err != nil {
				checks = append(checks, readinessCheck{
					Name:    "tls_material",
					OK:      false,
					Message: "TLS file not accessible: " + err.Error(),
				})
				certOK = false
				break
			}
		}
		if certOK {
			checks = append(checks, readinessCheck{Name: "tls_material", OK: true})
		}
	}

	return checks
}
