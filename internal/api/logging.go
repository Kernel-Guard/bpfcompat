package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// Logging environment knobs. Operators tune log shape via env so the binary
// stays config-free at startup.
const (
	// envLogLevel selects the slog level: debug, info (default), warn, error.
	envLogLevel = "BPFCOMPAT_LOG_LEVEL"
	// envLogFormat selects the slog handler: json (default) or text. JSON is
	// the right default for shipping into Loki/Elastic/Datadog; text is for
	// local dev.
	envLogFormat = "BPFCOMPAT_LOG_FORMAT"
	// headerRequestID lets clients propagate a trace ID into the server logs.
	// Missing/blank headers are filled with a fresh random ID.
	headerRequestID = "X-Request-Id"
	// headerTraceparent is the W3C Trace Context header. When present and
	// well-formed we surface trace_id/span_id in the request log line so
	// operators can correlate API calls with upstream distributed traces.
	// The header is echoed back unchanged so the next hop sees the same
	// trace context the caller propagated.
	headerTraceparent = "traceparent"
)

// requestIDContextKey is unexported so callers can only access the request ID
// via requestIDFromContext — no chance of collision with arbitrary strings.
type requestIDContextKey struct{}

// traceContextKey carries a parsed W3C Trace Context so handlers can fetch
// trace_id/span_id without re-parsing the header. Separate from
// requestIDContextKey because the request ID is always set (synthesized if
// the client omitted it) whereas trace context is only present when the
// caller propagated a valid traceparent.
type traceContextKey struct{}

// traceContext is the subset of W3C Trace Context fields we surface in
// logs. We deliberately do not parse tracestate (vendor-specific extension
// data) — the bytes are propagated verbatim by echoing the header back if
// we need them later, but we don't try to reason about them.
type traceContext struct {
	TraceID string
	SpanID  string
	Flags   string
}

// parseTraceparent validates the W3C Trace Context header. Format:
//
//	version-trace_id-parent_id-flags
//	00     -32hex   -16hex    -2hex
//
// Returns (ctx, true) only when every field is the exact length the spec
// requires AND the trace_id is not all-zero (per the spec, all-zero is the
// "invalid" sentinel). Malformed input returns zero-value, false — the
// caller treats that as "no upstream trace" rather than erroring the
// request.
func parseTraceparent(header string) (traceContext, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return traceContext{}, false
	}
	parts := strings.Split(header, "-")
	if len(parts) != 4 {
		return traceContext{}, false
	}
	version, traceID, spanID, flags := parts[0], parts[1], parts[2], parts[3]
	if len(version) != 2 || len(traceID) != 32 || len(spanID) != 16 || len(flags) != 2 {
		return traceContext{}, false
	}
	if !isLowerHex(version) || !isLowerHex(traceID) || !isLowerHex(spanID) || !isLowerHex(flags) {
		return traceContext{}, false
	}
	// "ff" version is reserved by the spec and signals "unknown future
	// version"; safest behavior is to drop the header rather than guess.
	if version == "ff" {
		return traceContext{}, false
	}
	if traceID == "00000000000000000000000000000000" {
		return traceContext{}, false
	}
	if spanID == "0000000000000000" {
		return traceContext{}, false
	}
	return traceContext{TraceID: traceID, SpanID: spanID, Flags: flags}, true
}

// isLowerHex reports whether s contains only [0-9a-f]. The W3C spec
// requires lowercase hex; uppercase is a hard format error per RFC.
func isLowerHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// contextWithTrace stashes parsed trace context for handlers that want to
// stamp trace IDs onto downstream calls (e.g., logs from runtime.fetch).
func contextWithTrace(ctx context.Context, tc traceContext) context.Context {
	if tc.TraceID == "" {
		return ctx
	}
	return context.WithValue(ctx, traceContextKey{}, tc)
}

// traceFromContext returns the propagated trace context or zero-value if
// the request had no valid traceparent.
func traceFromContext(ctx context.Context) traceContext {
	if ctx == nil {
		return traceContext{}
	}
	if tc, ok := ctx.Value(traceContextKey{}).(traceContext); ok {
		return tc
	}
	return traceContext{}
}

// newDefaultLogger reads the level/format from env and returns a slog.Logger
// suitable for the API server. The configured logger is set as the package
// default so any code calling slog.Default() in a request context will pick
// it up; callers in handler code should still prefer the request-scoped
// logger via loggerFromContext.
func newDefaultLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envLogLevel))) {
	case "debug":
		level = slog.LevelDebug
	case "info", "":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envLogFormat))) {
	case "text":
		handler = slog.NewTextHandler(os.Stderr, opts)
	default:
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	logger := slog.New(handler).With(
		slog.String("component", "bpfcompat-api"),
	)
	slog.SetDefault(logger)
	return logger
}

// contextWithRequestID returns a child context carrying the supplied request
// ID. Empty IDs are ignored so middleware can defensively call this.
func contextWithRequestID(ctx context.Context, requestID string) context.Context {
	if strings.TrimSpace(requestID) == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

// requestIDFromContext returns the propagated request ID or "" if none was
// injected.
func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		return v
	}
	return ""
}

// loggerFromContext returns a per-request logger pre-populated with the
// request ID label, falling back to the package default when nothing is in
// the context. Use this from handlers to emit log lines that auto-correlate.
// When a valid W3C traceparent rode the request in, trace_id/span_id are
// added too so the log line joins cleanly to upstream distributed traces.
func loggerFromContext(ctx context.Context) *slog.Logger {
	base := slog.Default()
	attrs := make([]any, 0, 3)
	if rid := requestIDFromContext(ctx); rid != "" {
		attrs = append(attrs, slog.String("request_id", rid))
	}
	if tc := traceFromContext(ctx); tc.TraceID != "" {
		attrs = append(attrs, slog.String("trace_id", tc.TraceID), slog.String("span_id", tc.SpanID))
	}
	if len(attrs) == 0 {
		return base
	}
	return base.With(attrs...)
}

// generateRequestID returns 16 random bytes hex-encoded. Falls back to a
// timestamp-based string only when crypto/rand is unavailable (effectively
// never on supported platforms).
func generateRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return hex.EncodeToString(buf)
}

// loggingResponseWriter captures the status code so we can include it in the
// access log. The default http.ResponseWriter swallows the status, leaving
// the middleware no way to record it.
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// withRequestLogging is HTTP middleware that:
//   - reads X-Request-Id (or generates a fresh ID if absent),
//   - propagates it via context to handlers + downstream logs,
//   - echoes it back in the response header so clients can correlate, and
//   - emits one structured log line per request at completion.
//
// We deliberately log at INFO for normal traffic; 5xx is bumped to ERROR so
// alerting platforms can route on level alone. The handler is wrapped in a
// recover() so a panicking handler still emits a log entry instead of
// silently dropping the request.
func withRequestLogging(next http.Handler, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get(headerRequestID))
		if requestID == "" {
			requestID = generateRequestID()
		}
		w.Header().Set(headerRequestID, requestID)
		ctx := contextWithRequestID(r.Context(), requestID)

		// Echo any valid W3C traceparent back to the caller verbatim so a
		// proxying client sees the same context it sent. Malformed headers
		// are dropped (not echoed) — that's the spec's "treat as no trace
		// context" path.
		tc, ok := parseTraceparent(r.Header.Get(headerTraceparent))
		if ok {
			w.Header().Set(headerTraceparent, r.Header.Get(headerTraceparent))
			ctx = contextWithTrace(ctx, tc)
		}
		r = r.WithContext(ctx)

		lw := &loggingResponseWriter{ResponseWriter: w}
		start := time.Now()
		defer func() {
			if rec := recover(); rec != nil {
				if lw.status == 0 {
					lw.WriteHeader(http.StatusInternalServerError)
				}
				attrs := []slog.Attr{
					slog.String("request_id", requestID),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Any("panic", rec),
				}
				attrs = appendTraceAttrs(attrs, tc, ok)
				logger.LogAttrs(ctx, slog.LevelError, "http request panicked", attrs...)
				return
			}
			status := lw.status
			if status == 0 {
				status = http.StatusOK
			}
			level := slog.LevelInfo
			switch {
			case status >= 500:
				level = slog.LevelError
			case status >= 400:
				level = slog.LevelWarn
			}
			attrs := []slog.Attr{
				slog.String("request_id", requestID),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Int("response_bytes", lw.bytes),
				slog.Duration("duration", time.Since(start)),
				slog.String("remote", r.RemoteAddr),
				slog.String("client_ip", clientIP(r)),
			}
			attrs = appendTraceAttrs(attrs, tc, ok)
			logger.LogAttrs(ctx, level, "http request", attrs...)
		}()
		next.ServeHTTP(lw, r)
	})
}

// appendTraceAttrs adds trace_id/span_id to the structured log attrs when
// the caller propagated a valid traceparent. Kept as a helper so the
// access-log and panic paths stay in sync.
func appendTraceAttrs(attrs []slog.Attr, tc traceContext, ok bool) []slog.Attr {
	if !ok {
		return attrs
	}
	return append(attrs, slog.String("trace_id", tc.TraceID), slog.String("span_id", tc.SpanID))
}
