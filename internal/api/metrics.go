package api

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics environment knobs.
const (
	// envEnableMetrics gates the /metrics endpoint and instrumentation.
	// Off by default so installs that don't run a scraper don't expose the
	// internal label cardinality. When on, /metrics is gated by the same
	// read-auth helper used for other read endpoints (so an authenticated
	// scraper bearer token / API key is required).
	envEnableMetrics = "BPFCOMPAT_API_ENABLE_METRICS"
)

// metricsState carries the metric handles. We lazy-init once so multiple
// Server instances within a single process (typical tests) share the same
// counters and don't double-register against the global registry.
var (
	metricsOnce sync.Once

	httpRequestsTotal *prometheus.CounterVec
	httpRequestDur    *prometheus.HistogramVec

	validateJobsActive   prometheus.Gauge
	validateJobsQueued   prometheus.Gauge
	validateJobsByState  *prometheus.CounterVec
	runtimeFetchOutcomes *prometheus.CounterVec
	runtimeExecOutcomes  *prometheus.CounterVec
	registryRateDrops    *prometheus.CounterVec
)

// initMetrics registers metrics with the default registry. Safe to call from
// every Serve(); the sync.Once ensures we register exactly once across the
// lifetime of the process.
func initMetrics() {
	metricsOnce.Do(func() {
		// The default prometheus.Registerer already includes Go runtime and
		// process collectors out of the box, so we only register our custom
		// metrics here. Re-registering the defaults would panic.

		httpRequestsTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bpfcompat_http_requests_total",
				Help: "Total HTTP requests handled by the bpfcompat API server.",
			},
			[]string{"method", "route", "status"},
		)
		httpRequestDur = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "bpfcompat_http_request_duration_seconds",
				Help:    "Latency of HTTP requests handled by the bpfcompat API server.",
				Buckets: prometheus.ExponentialBuckets(0.005, 2, 12), // 5ms .. ~10s
			},
			[]string{"method", "route"},
		)
		validateJobsActive = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bpfcompat_validate_jobs_active",
				Help: "Number of validate jobs currently in the running state.",
			},
		)
		validateJobsQueued = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bpfcompat_validate_jobs_queued",
				Help: "Number of validate jobs currently in the queued state.",
			},
		)
		validateJobsByState = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bpfcompat_validate_jobs_state_transitions_total",
				Help: "Validate jobs counted by terminal state (completed, failed).",
			},
			[]string{"state"},
		)
		runtimeFetchOutcomes = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bpfcompat_runtime_fetch_total",
				Help: "Runtime fetch operations counted by outcome (success/error).",
			},
			[]string{"outcome"},
		)
		runtimeExecOutcomes = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bpfcompat_runtime_execute_total",
				Help: "Runtime execute operations counted by terminal outcome.",
			},
			[]string{"outcome"},
		)
		registryRateDrops = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bpfcompat_registry_rate_limit_drops_total",
				Help: "Requests rejected by the cloud-registry rate limiter, by action.",
			},
			[]string{"action"},
		)

		prometheus.MustRegister(
			httpRequestsTotal,
			httpRequestDur,
			validateJobsActive,
			validateJobsQueued,
			validateJobsByState,
			runtimeFetchOutcomes,
			runtimeExecOutcomes,
			registryRateDrops,
		)
	})
}

// metricsEnabled returns whether instrumentation is on for this server.
// We expose it as a free function (not a method on Server) because the
// middleware needs to ask before it has access to a Server.
func metricsEnabled() bool {
	return parseBoolEnv(envEnableMetrics, false)
}

// withMetrics is HTTP middleware that records request count and latency. The
// route label uses the registered pattern (e.g., "/api/runtime/fetch") rather
// than the request URI to avoid unbounded label cardinality from query
// strings or path traversal attempts.
//
// We intentionally place withMetrics inside withRequestLogging so the access
// log line and the metric increment cover the same response status.
func withMetrics(next http.Handler) http.Handler {
	if !metricsEnabled() {
		return next
	}
	initMetrics()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lw, r)
		status := lw.status
		if status == 0 {
			status = http.StatusOK
		}
		route := normalizeMetricsRoute(r.URL.Path)
		httpRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(status)).Inc()
		httpRequestDur.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
	})
}

// normalizeMetricsRoute collapses request paths into the small set of
// registered routes so labels stay bounded. Anything that doesn't match a
// known prefix collapses to "other" so we never blow up the cardinality.
func normalizeMetricsRoute(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "other"
	}
	if path == "/" || path == "/metrics" {
		return path
	}
	if strings.HasPrefix(path, "/api/") {
		// /api/registry/artifacts/upload, /api/runtime/fetch, etc.
		// One path segment after /api/ is plenty for SRE dashboards.
		segments := strings.Split(strings.TrimPrefix(path, "/api/"), "/")
		switch len(segments) {
		case 0:
			return "/api"
		case 1:
			return "/api/" + segments[0]
		default:
			return "/api/" + segments[0] + "/" + segments[1]
		}
	}
	if path == "/results" || path == "/demo-result" {
		return path
	}
	return "other"
}

// metricsHandler returns an HTTP handler that serves the Prometheus text
// exposition format. The handler is gated upstream by the same read-auth
// middleware that protects /api/history/*, so unauthenticated scrapers
// cannot harvest fingerprinting data.
func metricsHandler() http.Handler {
	initMetrics()
	return promhttp.Handler()
}

// recordValidateJobsGauge updates the active/queued gauges from a snapshot.
// Called from places that already hold the validateJobs lock; expects active
// and queued counts as the source of truth.
func recordValidateJobsGauge(active, queued int) {
	if !metricsEnabled() {
		return
	}
	initMetrics()
	validateJobsActive.Set(float64(active))
	validateJobsQueued.Set(float64(queued))
}

// recordValidateJobTerminal bumps the state-transition counter when a job
// reaches a terminal state. The state argument is "completed" or "failed";
// other states are accepted but discouraged.
func recordValidateJobTerminal(state string) {
	if !metricsEnabled() {
		return
	}
	initMetrics()
	state = strings.TrimSpace(strings.ToLower(state))
	if state == "" {
		state = "unknown"
	}
	validateJobsByState.WithLabelValues(state).Inc()
}

// recordRuntimeFetchOutcome bumps the runtime-fetch outcome counter. Common
// outcomes: "success", "ssrf_blocked", "hash_mismatch", "fetch_error".
func recordRuntimeFetchOutcome(outcome string) {
	if !metricsEnabled() {
		return
	}
	initMetrics()
	outcome = strings.TrimSpace(strings.ToLower(outcome))
	if outcome == "" {
		outcome = "unknown"
	}
	runtimeFetchOutcomes.WithLabelValues(outcome).Inc()
}

// recordRuntimeExecuteOutcome bumps the runtime-execute counter.
func recordRuntimeExecuteOutcome(outcome string) {
	if !metricsEnabled() {
		return
	}
	initMetrics()
	outcome = strings.TrimSpace(strings.ToLower(outcome))
	if outcome == "" {
		outcome = "unknown"
	}
	runtimeExecOutcomes.WithLabelValues(outcome).Inc()
}

// recordRegistryRateLimitDrop is invoked from the rate-limiter when it
// denies a request. Visibility into rate-limit drops is critical for
// distinguishing "noisy tenant" from "platform incident" on call.
func recordRegistryRateLimitDrop(action string) {
	if !metricsEnabled() {
		return
	}
	initMetrics()
	action = strings.TrimSpace(strings.ToLower(action))
	if action == "" {
		action = "unknown"
	}
	registryRateDrops.WithLabelValues(action).Inc()
}
