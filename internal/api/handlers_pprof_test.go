package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPprofGatedOffByDefault confirms the env flag has to be flipped on for
// the endpoint to register. Off-by-default is the security-load-bearing
// behavior — pprof exposes goroutine stacks, so a misconfigured deployment
// should not accidentally publish them.
func TestPprofGatedOffByDefault(t *testing.T) {
	t.Setenv(envEnablePprof, "")
	if pprofEnabled() {
		t.Fatalf("expected pprofEnabled() to be false when env unset")
	}
	t.Setenv(envEnablePprof, "true")
	if !pprofEnabled() {
		t.Fatalf("expected pprofEnabled() to be true when env=true")
	}
}

// TestPprofHandlerRequiresAuth asserts that even when the endpoint is
// enabled, anonymous callers get a 401 by default — the auth gate runs
// before the standard library pprof handler.
func TestPprofHandlerRequiresAuth(t *testing.T) {
	t.Setenv(envEnablePprof, "true")
	t.Setenv(envWriteAPIKey, "test-key")
	t.Setenv(envWriteRequireIdentity, "")
	t.Setenv(envAllowAnonymousRead, "")
	t.Setenv(envAllowAnonymousWrite, "")
	t.Setenv(envAllowAnonymousValidate, "")

	s := &Server{}
	handler := s.handlePprof()

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestPprofHandlerIgnoresAnonymousModes protects the live-demo posture:
// /results and history may be public, but pprof must remain admin-only
// because it exposes stack and heap internals.
func TestPprofHandlerIgnoresAnonymousModes(t *testing.T) {
	t.Setenv(envEnablePprof, "true")
	t.Setenv(envWriteAPIKey, "test-key")
	t.Setenv(envWriteRequireIdentity, "")
	t.Setenv(envAllowAnonymousRead, "true")
	t.Setenv(envAllowAnonymousWrite, "true")
	t.Setenv(envAllowAnonymousValidate, "true")

	s := &Server{}
	handler := s.handlePprof()

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth even when anonymous modes are enabled, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestPprofHandlerServesIndexWithAuth uses the API key auth path to confirm
// the underlying pprof handler runs once the auth gate is satisfied. We
// hit the index page because it's deterministic and tiny; the heavier
// /profile/heap endpoints are not worth invoking in a unit test.
func TestPprofHandlerServesIndexWithAuth(t *testing.T) {
	t.Setenv(envEnablePprof, "true")
	t.Setenv(envWriteAPIKey, "test-key")
	t.Setenv(envWriteRequireIdentity, "")
	t.Setenv(envAllowAnonymousRead, "")
	t.Setenv(envAllowAnonymousWrite, "")
	t.Setenv(envAllowAnonymousValidate, "")

	s := &Server{}
	handler := s.handlePprof()

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	req.Header.Set("X-API-Key", "test-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with auth, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// The pprof index page lists the standard profile names. We assert on
	// a couple so a regression in the wiring (e.g., serving an empty body)
	// would fail loudly.
	for _, want := range []string{"heap", "goroutine"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected pprof index to mention %q, body=%s", want, body)
		}
	}
}

// TestPprofHandlerRejectsNonPprofPath protects against the handler being
// accidentally mounted under a prefix where it would happily serve other
// routes' paths back from the pprof Index. The handler must enforce its
// own path prefix.
func TestPprofHandlerRejectsNonPprofPath(t *testing.T) {
	t.Setenv(envEnablePprof, "true")
	t.Setenv(envAllowAnonymousRead, "true")

	s := &Server{}
	handler := s.handlePprof()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-pprof path, got %d body=%s", rec.Code, rec.Body.String())
	}
}
