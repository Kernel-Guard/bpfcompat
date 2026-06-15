package api

import (
	"net/http"
	"os"
	"path/filepath"
)

// The bundled "try our sample" artifact is the aegis security probe. It is
// served publicly so the web UI empty state can drop it into the validate form
// and run a real compatibility matrix. aegis uses a bloom-filter map
// (BPF_MAP_TYPE_BLOOM_FILTER, kernel 5.16+), so it loads on >= 5.16 and fails
// below — a precise, real compatibility boundary. See examples/aegis-live/.

// sampleArtifactPath returns the path to the bundled sample .bpf.o, overridable
// with BPFCOMPAT_SAMPLE_ARTIFACT for non-repo-root deployments (e.g. the demo).
func sampleArtifactPath() string {
	if p := os.Getenv("BPFCOMPAT_SAMPLE_ARTIFACT"); p != "" {
		return p
	}
	return filepath.FromSlash("examples/aegis-live/aegis.bpf.o")
}

// handleSampleArtifact serves the bundled aegis sample object for the
// "Try our aegis sample" empty-state button. Intentionally public (no auth):
// it is a published sample artifact, not user data.
func (s *Server) handleSampleArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Fixed, operator-controlled sample path (default or BPFCOMPAT_SAMPLE_ARTIFACT).
	path := filepath.Clean(sampleArtifactPath())
	data, err := os.ReadFile(path) // #nosec G304 -- fixed sample path, not user input
	if err != nil {
		writeError(w, http.StatusNotFound, "sample artifact not available")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis.bpf.o"`)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(data)
}
