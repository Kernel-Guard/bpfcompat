package api

import (
	"net/http"
	"net/http/pprof"
	"strings"
)

// envEnablePprof gates the /debug/pprof/* admin endpoints. Off by default
// because pprof exposes goroutine stacks and heap addresses; any operator
// flipping this on accepts that risk. When on, the endpoints require a real
// API/JWT credential and deliberately ignore anonymous demo read/write
// switches.
const envEnablePprof = "BPFCOMPAT_API_ENABLE_PPROF"

// pprofEnabled reports whether the operator opted into the runtime profile
// endpoints. Exposed as a free function (matching metricsEnabled) so the
// route registration code can ask before constructing a Server.
func pprofEnabled() bool {
	return parseBoolEnv(envEnablePprof, false)
}

// pprofMux returns a mux that serves the standard net/http/pprof handlers
// under the /debug/pprof/ prefix. Every request is first run through an
// authenticated admin gate so anonymous callers get a 401 even on public
// demo deployments.
//
// We register the handlers on our own mux rather than http.DefaultServeMux
// because importing net/http/pprof for its side effects would expose pprof
// on the default mux globally, which is not what we want for a hardened
// build.
func pprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// handlePprof wraps the pprof mux with a strict authenticated auth check.
// The action label "pprof" surfaces in audit logs so operators can spot
// when a credential is being used to pull profiles — useful in incident
// review when someone runs `go tool pprof` against the prod endpoint.
func (s *Server) handlePprof() http.Handler {
	inner := pprofMux()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only GET is meaningful; HEAD is allowed because some load
		// balancers use it for path discovery.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/debug/pprof/") {
			http.NotFound(w, r)
			return
		}
		if _, ok := requireAuthenticatedAuthorizationForAction(w, r, "pprof"); !ok {
			return
		}
		inner.ServeHTTP(w, r)
	})
}
