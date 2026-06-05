package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/erenari/bpfcompat/internal/registry"
)

// History endpoints expose the local artifact + run registry to authorized
// readers. They share the same read-auth gate (added in P0/H-1b) so the
// validate-status enumeration class of bugs can't sneak back in. The list
// handlers cap result counts via the limit query param; downstream
// registry.ListXxx layers enforce their own sanity bounds too.

func (s *Server) handleHistoryArtifacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireReadAuthorizationForAction(w, r, "history_artifacts"); !ok {
		return
	}
	limit := parseIntOrDefault(r.URL.Query().Get("limit"), 200)
	artifactName := strings.TrimSpace(r.URL.Query().Get("artifact_name"))

	records, err := registry.ListArtifactVersions(s.cfg.WorkDir, artifactName, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

func (s *Server) handleHistoryRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireReadAuthorizationForAction(w, r, "history_runs"); !ok {
		return
	}
	limit := parseIntOrDefault(r.URL.Query().Get("limit"), 200)

	records, err := registry.ListRunRecords(s.cfg.WorkDir, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

func (s *Server) handleRunReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireReadAuthorizationForAction(w, r, "run_report"); !ok {
		return
	}
	runID := strings.TrimSpace(r.URL.Query().Get("run_id"))
	if runID == "" {
		writeError(w, http.StatusBadRequest, "run_id is required")
		return
	}
	record, err := registry.GetRunRecord(s.cfg.WorkDir, runID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, registry.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}

	raw, err := os.ReadFile(filepath.Clean(record.JSONReportPath))
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("read report: %v", err))
		return
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("parse report: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run_id": runID, "report": report})
}
