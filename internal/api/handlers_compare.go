package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/erenari/bpfcompat/internal/compare"
	"github.com/erenari/bpfcompat/internal/registry"
)

// handleCompare diffs two reports either supplied directly or resolved from
// the local registry by artifact + version. Both paths run through
// resolveServerLocalReportPath so a caller can't trick the server into
// reading files outside the configured workdir / reports directory.
func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireWriteAuthorizationForAction(w, r, "compare"); !ok {
		return
	}

	var req compareRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	basePath := strings.TrimSpace(req.BaseReport)
	headPath := strings.TrimSpace(req.HeadReport)

	if basePath == "" || headPath == "" {
		if strings.TrimSpace(req.ArtifactName) == "" || strings.TrimSpace(req.BaseVersion) == "" || strings.TrimSpace(req.HeadVersion) == "" {
			writeError(w, http.StatusBadRequest, "provide base_report/head_report or artifact_name + base_version + head_version")
			return
		}

		baseRecord, err := registry.FindArtifactVersion(s.cfg.WorkDir, req.ArtifactName, req.BaseVersion)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, registry.ErrNotFound) {
				status = http.StatusNotFound
			}
			writeError(w, status, fmt.Sprintf("resolve base version: %v", err))
			return
		}
		headRecord, err := registry.FindArtifactVersion(s.cfg.WorkDir, req.ArtifactName, req.HeadVersion)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, registry.ErrNotFound) {
				status = http.StatusNotFound
			}
			writeError(w, status, fmt.Sprintf("resolve head version: %v", err))
			return
		}
		basePath = baseRecord.JSONReportPath
		headPath = headRecord.JSONReportPath
	}

	resolvedBase, err := resolveServerLocalReportPath(s.cfg.WorkDir, basePath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "base_report must be a server-local report under the configured workdir or reports directory")
		return
	}
	resolvedHead, err := resolveServerLocalReportPath(s.cfg.WorkDir, headPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "head_report must be a server-local report under the configured workdir or reports directory")
		return
	}

	diff, err := compare.LoadAndBuild(resolvedBase, resolvedHead)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"diff": diff})
}
