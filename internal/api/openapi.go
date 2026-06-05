package api

import (
	_ "embed"
	"net/http"
)

// openapiSpec is the OpenAPI 3.1 document for the bpfcompat HTTP API,
// embedded at build time. Editing docs/openapi.yaml updates both the
// in-tree documentation and the response served from
// /api/openapi.yaml so they cannot drift.
//
//go:embed openapi_spec.yaml
var openapiSpec []byte

// handleOpenAPISpec serves the bundled OpenAPI document. Clients use it to
// autogenerate SDKs; we serve it from a stable URL on the running server
// rather than expecting consumers to clone the repo. No auth — the spec
// describes only public route shapes and carries no secrets.
func handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(openapiSpec)
}
