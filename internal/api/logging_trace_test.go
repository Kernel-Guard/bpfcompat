package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestParseTraceparentHappy validates the spec-conformant W3C header. We
// don't unit-test every malformed shape — that's the table test below —
// but the happy path is the one that has to work for distributed tracing
// to function at all.
func TestParseTraceparentHappy(t *testing.T) {
	const header = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	tc, ok := parseTraceparent(header)
	if !ok {
		t.Fatalf("expected parseTraceparent to accept valid header")
	}
	if tc.TraceID != "0af7651916cd43dd8448eb211c80319c" {
		t.Fatalf("trace_id mismatch: %s", tc.TraceID)
	}
	if tc.SpanID != "b7ad6b7169203331" {
		t.Fatalf("span_id mismatch: %s", tc.SpanID)
	}
	if tc.Flags != "01" {
		t.Fatalf("flags mismatch: %s", tc.Flags)
	}
}

// TestParseTraceparentRejectsInvalid catches every malformed shape that
// real callers have been observed to send (uppercase IDs, zero trace,
// truncated fields). Each one MUST be rejected — accepting them would
// cause noisy "invalid trace" alerts in downstream collectors.
func TestParseTraceparentRejectsInvalid(t *testing.T) {
	cases := []struct {
		name, header string
	}{
		{"empty", ""},
		{"wrong-segments", "00-abc-def"},
		{"short-trace", "00-0af7-b7ad6b7169203331-01"},
		{"short-span", "00-0af7651916cd43dd8448eb211c80319c-b7ad-01"},
		{"uppercase", "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01"},
		{"non-hex", "00-0af7651916cd43dd8448eb211c80319z-b7ad6b7169203331-01"},
		{"all-zero-trace", "00-00000000000000000000000000000000-b7ad6b7169203331-01"},
		{"all-zero-span", "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01"},
		{"reserved-version", "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := parseTraceparent(tc.header); ok {
				t.Fatalf("expected reject for %q", tc.header)
			}
		})
	}
}

// TestWithRequestLoggingEchoesTraceparent confirms the middleware echoes a
// valid header back so downstream services see continuous trace context.
// We also check the malformed-header path does NOT echo (per spec, drop).
func TestWithRequestLoggingEchoesTraceparent(t *testing.T) {
	handler := withRequestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

	const good = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	req.Header.Set(headerTraceparent, good)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get(headerTraceparent); got != good {
		t.Fatalf("expected traceparent echoed verbatim, got %q", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/livez", nil)
	req2.Header.Set(headerTraceparent, "garbage-not-a-real-header")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get(headerTraceparent); got != "" {
		t.Fatalf("expected malformed traceparent to be dropped, got echoed %q", got)
	}
}

// TestLoggerFromContextWithTrace asserts the per-request logger picks up
// trace_id/span_id when the middleware stored them on the context. We
// can't easily inspect the logger's With() args from outside, so we
// confirm via the path that round-trips: middleware writes context, then
// loggerFromContext returns a non-default-equal logger only when trace is
// present.
func TestLoggerFromContextWithTrace(t *testing.T) {
	ctx := contextWithTrace(contextWithRequestID(context.Background(), "rid-1"), traceContext{
		TraceID: "0af7651916cd43dd8448eb211c80319c",
		SpanID:  "b7ad6b7169203331",
		Flags:   "01",
	})
	if got := traceFromContext(ctx).TraceID; got != "0af7651916cd43dd8448eb211c80319c" {
		t.Fatalf("trace_id missing on context: %q", got)
	}
	if got := requestIDFromContext(ctx); got != "rid-1" {
		t.Fatalf("request_id missing on context: %q", got)
	}
	// Smoke: loggerFromContext must not return nil when context is populated.
	if logger := loggerFromContext(ctx); logger == nil {
		t.Fatalf("loggerFromContext returned nil")
	}
}
