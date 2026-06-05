package api

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeJSONBodyRejectsOversizedPayload regresses P0-2. A request body
// over maxJSONRequestBytes must be rejected without parsing the contents so
// a hostile client can't OOM the server by streaming a multi-GiB body.
func TestDecodeJSONBodyRejectsOversizedPayload(t *testing.T) {
	// Build a JSON payload guaranteed to exceed the cap. Padding with a long
	// "extra" field that isn't part of any real request type also exercises
	// the DisallowUnknownFields branch — but the size check runs first via
	// MaxBytesReader.
	big := make([]byte, maxJSONRequestBytes+1024)
	for i := range big {
		big[i] = 'x'
	}
	payload := []byte(`{"base_report":"`)
	payload = append(payload, big...)
	payload = append(payload, []byte(`"}`)...)

	req := httptest.NewRequest(http.MethodPost, "/api/compare", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	var dst struct {
		BaseReport string `json:"base_report"`
	}
	err := decodeJSONBody(rec, req, &dst)
	if err == nil {
		t.Fatalf("expected oversize body to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds") && !strings.Contains(err.Error(), "request body") {
		t.Fatalf("expected body-size error, got %v", err)
	}
}

// TestDecodeJSONBodyRejectsTrailingJSON regresses P0-2's smuggling guard.
// Two JSON values back-to-back used to slip past the standard decoder; the
// helper requires exactly one value.
func TestDecodeJSONBodyRejectsTrailingJSON(t *testing.T) {
	body := strings.NewReader(`{"base_report":"a"}{"head_report":"b"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/compare", body)
	rec := httptest.NewRecorder()
	var dst compareRequest
	err := decodeJSONBody(rec, req, &dst)
	if err == nil {
		t.Fatalf("expected trailing JSON to be rejected")
	}
	if !strings.Contains(err.Error(), "exactly one JSON value") {
		t.Fatalf("expected smuggling rejection, got %v", err)
	}
}

// TestDecodeJSONBodyRejectsUnknownFields regresses P0-2's DisallowUnknownFields
// posture. Clients with a future schema must opt into a versioned endpoint
// instead of silently dropping their unrecognized fields.
func TestDecodeJSONBodyRejectsUnknownFields(t *testing.T) {
	body := strings.NewReader(`{"base_report":"a","mystery":"x"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/compare", body)
	rec := httptest.NewRecorder()
	var dst compareRequest
	err := decodeJSONBody(rec, req, &dst)
	if err == nil {
		t.Fatalf("expected unknown field to be rejected")
	}
}

// TestRequestLoggingEmitsRequestID regresses P0-3. Every request gets either
// the propagated X-Request-Id or a freshly generated 32-hex-char ID, and the
// same ID is echoed back to the caller so they can correlate logs.
func TestRequestLoggingEmitsRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := withRequestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}), logger)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	id := rec.Header().Get(headerRequestID)
	if id == "" {
		t.Fatalf("expected response to carry X-Request-Id header")
	}
	if len(id) != 32 {
		t.Fatalf("expected 16-byte hex request ID (32 chars), got %d (%q)", len(id), id)
	}
	if !strings.Contains(buf.String(), id) {
		t.Fatalf("expected log line to include request id %q, got: %s", id, buf.String())
	}
}

// TestRequestLoggingPropagatesIncomingID confirms that an X-Request-Id header
// supplied by the client is reused (not replaced) so trace correlation works
// across a hop.
func TestRequestLoggingPropagatesIncomingID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := withRequestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := requestIDFromContext(r.Context()); got != "client-trace-1" {
			t.Fatalf("expected propagated request_id in context, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}), logger)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set(headerRequestID, "client-trace-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get(headerRequestID) != "client-trace-1" {
		t.Fatalf("expected response header to echo client request id")
	}
}

// TestServerHTTPHardeningTimeouts regresses P0-1. We can't easily probe the
// real http.Server's behavior without standing it up, but we can assert the
// struct fields were set, which is what the framework consults.
func TestServerHTTPHardeningConstants(t *testing.T) {
	if httpServerReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout must be positive")
	}
	if httpServerReadTimeout <= 0 {
		t.Fatalf("ReadTimeout must be positive")
	}
	if httpServerIdleTimeout <= 0 {
		t.Fatalf("IdleTimeout must be positive")
	}
	if httpServerMaxHeaderBytes <= 0 {
		t.Fatalf("MaxHeaderBytes must be positive")
	}
}

// TestNormalizeMetricsRouteBoundsCardinality regresses P0-4. Without this
// bound a malicious client could explode Prometheus label cardinality by
// sending unique paths.
func TestNormalizeMetricsRouteBoundsCardinality(t *testing.T) {
	cases := map[string]string{
		"/":                              "/",
		"/metrics":                       "/metrics",
		"/api/runtime/fetch":             "/api/runtime/fetch",
		"/api/runtime/execute":           "/api/runtime/execute",
		"/api/registry/artifacts/upload": "/api/registry/artifacts",
		"/api/registry/artifacts/download/garbage": "/api/registry/artifacts",
		"/api/runtime/some-future-route":           "/api/runtime/some-future-route",
		"/etc/passwd":                              "other",
		"/results":                                 "/results",
		"":                                         "other",
	}
	for input, want := range cases {
		got := normalizeMetricsRoute(input)
		if got != want {
			t.Fatalf("normalizeMetricsRoute(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestMetricsEndpointRequiresAuth regresses P0-4 + H-1b. When metrics are
// enabled but no anonymous read is configured, /metrics must require auth.
func TestMetricsEndpointRequiresAuth(t *testing.T) {
	t.Setenv(envEnableMetrics, "true")
	t.Setenv(envWriteAPIKey, "")
	t.Setenv(envAllowAnonymousRead, "")
	t.Setenv(envAllowAnonymousWrite, "")

	s := &Server{}
	handler := s.handleMetrics()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("expected /metrics to require auth, got 200 body=%s", rec.Body.String())
	}
}

func TestMetricsEndpointServesWhenAuthorized(t *testing.T) {
	t.Setenv(envEnableMetrics, "true")
	t.Setenv(envWriteAPIKey, "scrape-key")
	// Ensure validate gauges have been touched at least once so we have a
	// stable metric in the output to match on.
	initMetrics()
	recordValidateJobsGauge(0, 0)

	s := &Server{}
	handler := s.handleMetrics()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set(headerAPIKey, "scrape-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for authorized scrape, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "bpfcompat_validate_jobs_active") {
		t.Fatalf("expected exposition to contain validate_jobs_active, got %s", rec.Body.String())
	}
}

func TestClientIPUsesRightmostUntrustedForwardedAddress(t *testing.T) {
	t.Setenv(envTrustedProxies, "10.0.0.1/32")

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.RemoteAddr = "10.0.0.1:443"
	// The client controls the leftmost spoofed address. The trusted proxy
	// appends its own hop on the right, so the correct client is the
	// rightmost non-trusted entry, not the first entry in the header.
	req.Header.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.20, 10.0.0.1")

	if got := clientIP(req); got != "203.0.113.20" {
		t.Fatalf("clientIP returned %q, want rightmost untrusted client 203.0.113.20", got)
	}
}

func TestDemoResultUsesNonceCSP(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/results", nil)
	rec := httptest.NewRecorder()

	s.handleDemoResult(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatalf("expected CSP header")
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP must not rely on unsafe-inline: %s", csp)
	}
	body := rec.Body.String()
	if strings.Contains(body, "__CSP_NONCE__") {
		t.Fatalf("expected CSP nonce placeholders to be replaced")
	}
	if !strings.Contains(body, "<style nonce=") || !strings.Contains(body, "<script nonce=") {
		t.Fatalf("expected nonce-bearing style and script tags")
	}
	if strings.Contains(body, "style=") {
		t.Fatalf("results page should not use inline style attributes under strict CSP")
	}
}

func TestRuntimeMetricsIncrementFromHandlers(t *testing.T) {
	t.Setenv(envEnableMetrics, "true")
	t.Setenv(envWriteAPIKey, "scrape-key")
	t.Setenv(envAllowRuntimeExec, "")

	s := &Server{}

	fetchReq := httptest.NewRequest(http.MethodPost, "/api/runtime/fetch", strings.NewReader(`{}`))
	fetchRec := httptest.NewRecorder()
	s.handleRuntimeFetch(fetchRec, fetchReq)

	execReq := httptest.NewRequest(http.MethodPost, "/api/runtime/execute", strings.NewReader(`{}`))
	execReq.Header.Set(headerAPIKey, "scrape-key")
	execRec := httptest.NewRecorder()
	s.handleRuntimeExecute(execRec, execReq)

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsReq.Header.Set(headerAPIKey, "scrape-key")
	metricsRec := httptest.NewRecorder()
	s.handleMetrics().ServeHTTP(metricsRec, metricsReq)

	body := metricsRec.Body.String()
	if !strings.Contains(body, `bpfcompat_runtime_fetch_total{outcome="auth_denied"}`) {
		t.Fatalf("expected runtime fetch auth_denied metric, got:\n%s", body)
	}
	if !strings.Contains(body, `bpfcompat_runtime_execute_total{outcome="disabled"}`) {
		t.Fatalf("expected runtime execute disabled metric, got:\n%s", body)
	}
}
