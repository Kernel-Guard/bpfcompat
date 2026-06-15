package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/agent"
	"github.com/kernel-guard/bpfcompat/internal/cloudregistry"
	"github.com/kernel-guard/bpfcompat/internal/manifest"
	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/internal/runtime"
	"github.com/kernel-guard/bpfcompat/internal/version"
	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
	"gopkg.in/yaml.v3"
)

const (
	defaultAddr           = ":8080"
	defaultConcurrency    = 2
	defaultTimeout        = 8 * time.Minute
	maxMultipartFormBytes = 128 << 20
	// maxJSONRequestBytes caps the body size that decodeJSONBody will read.
	// JSON handlers carry small request shapes (compare/select/fetch/execute);
	// a hard cap protects the process from a hostile or buggy caller sending
	// an unbounded payload that would otherwise be streamed into memory.
	maxJSONRequestBytes = 1 << 20 // 1 MiB
	// httpServerReadHeaderTimeout caps the time we'll wait for a client to
	// finish sending request headers. Slow-loris connections that send a
	// byte every few seconds used to be able to park sockets indefinitely.
	httpServerReadHeaderTimeout = 10 * time.Second
	// httpServerReadTimeout bounds the time for the full request body —
	// generous because multipart uploads can be 128 MiB on slow links.
	httpServerReadTimeout = 5 * time.Minute
	// httpServerIdleTimeout closes idle keep-alive connections so clients
	// can't tie up server resources between requests.
	httpServerIdleTimeout = 2 * time.Minute
	// httpServerMaxHeaderBytes caps total header size. The Go default is
	// 1 MiB which is generous; 64 KiB is comfortable for any sane client.
	httpServerMaxHeaderBytes = 64 << 10
	// httpShutdownTimeout bounds the wait for in-flight HTTP handlers to
	// return after the context cancels. Validate jobs run on their own
	// goroutines and are drained separately via inflight.WaitGroup.
	httpShutdownTimeout = 15 * time.Second
	// defaultShutdownDrainTimeout is the upper bound on waiting for async
	// validate jobs. Realistically a job completes in <= cfg.DefaultTimeout
	// (8 min default), so 10 minutes is a comfortable margin. Overridable
	// via env so air-gapped customers with long VM warm-up can tune up.
	defaultShutdownDrainTimeout         = 10 * time.Minute
	envShutdownDrainTimeout             = "BPFCOMPAT_API_SHUTDOWN_DRAIN_TIMEOUT"
	envWriteAPIKey                      = "BPFCOMPAT_API_WRITE_KEY"
	envWriteJWTSecret                   = "BPFCOMPAT_API_WRITE_JWT_HS256_SECRET"
	envWriteJWTJWKSPath                 = "BPFCOMPAT_API_WRITE_JWT_JWKS_PATH"
	envWriteJWTJWKSURL                  = "BPFCOMPAT_API_WRITE_JWT_JWKS_URL"
	envWriteJWTJWKSCacheTTL             = "BPFCOMPAT_API_WRITE_JWT_JWKS_CACHE_TTL"
	envWriteJWTJWKSHTTPTimeout          = "BPFCOMPAT_API_WRITE_JWT_JWKS_HTTP_TIMEOUT"
	envWriteJWTOIDCIssuerURL            = "BPFCOMPAT_API_WRITE_JWT_OIDC_ISSUER_URL"
	envWriteJWTOIDCDiscoveryCacheTTL    = "BPFCOMPAT_API_WRITE_JWT_OIDC_DISCOVERY_CACHE_TTL"
	envWriteJWTRequiredScopes           = "BPFCOMPAT_API_WRITE_JWT_REQUIRED_SCOPES"
	envWriteJWTRequiredRoles            = "BPFCOMPAT_API_WRITE_JWT_REQUIRED_ROLES"
	envRuntimeExecJWTRequiredScopes     = "BPFCOMPAT_API_RUNTIME_EXECUTE_JWT_REQUIRED_SCOPES"
	envRuntimeExecJWTRequiredRoles      = "BPFCOMPAT_API_RUNTIME_EXECUTE_JWT_REQUIRED_ROLES"
	envRegistryRequireIdentity          = "BPFCOMPAT_API_REGISTRY_REQUIRE_IDENTITY"
	envWriteRequireIdentity             = "BPFCOMPAT_API_WRITE_REQUIRE_IDENTITY"
	envAllowAnonymousValidate           = "BPFCOMPAT_API_ALLOW_ANONYMOUS_VALIDATE"
	envAllowAnonymousWrite              = "BPFCOMPAT_API_ALLOW_ANONYMOUS_WRITE"
	envAllowAnonymousRuntimeDelivery    = "BPFCOMPAT_API_ALLOW_ANONYMOUS_RUNTIME_DELIVERY"
	envWriteJWTIssuer                   = "BPFCOMPAT_API_WRITE_JWT_ISSUER"
	envWriteJWTAudience                 = "BPFCOMPAT_API_WRITE_JWT_AUDIENCE"
	envAllowRuntimeExec                 = "BPFCOMPAT_API_ENABLE_RUNTIME_EXECUTE"
	envRedactRuntime                    = "BPFCOMPAT_API_REDACT_RUNTIME_DETAILS"
	envRuntimeExecApprove               = "BPFCOMPAT_API_RUNTIME_EXECUTE_APPROVAL_TOKEN"
	envRuntimeExecKill                  = "BPFCOMPAT_API_RUNTIME_EXECUTE_KILL_SWITCH"
	envRuntimeExecWorker                = "BPFCOMPAT_API_RUNTIME_EXECUTE_WORKER_BINARY"
	envRuntimeExecWorkerUser            = "BPFCOMPAT_API_RUNTIME_EXECUTE_WORKER_USER"
	envRuntimeExecRequireWorkerIdentity = "BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_WORKER_IDENTITY"
	envRuntimeExecPolicyPath            = "BPFCOMPAT_API_RUNTIME_EXECUTE_POLICY_PATH"
	envRuntimeExecRequirePolicy         = "BPFCOMPAT_API_RUNTIME_EXECUTE_REQUIRE_POLICY"
	envAutoSyncRegistry                 = "BPFCOMPAT_API_AUTO_SYNC_REGISTRY"
	envAutoSyncTenant                   = "BPFCOMPAT_API_AUTO_SYNC_TENANT"
	envAutoSyncProject                  = "BPFCOMPAT_API_AUTO_SYNC_PROJECT"
	envAutoSyncProjectVisibility        = "BPFCOMPAT_API_AUTO_SYNC_PROJECT_VISIBILITY"
	envMaxActiveValidateJobs            = "BPFCOMPAT_API_MAX_ACTIVE_VALIDATE_JOBS"
	envMaxQueuedValidateJobs            = "BPFCOMPAT_API_MAX_QUEUED_VALIDATE_JOBS"
	envMaxValidateConcurrency           = "BPFCOMPAT_API_MAX_VALIDATE_CONCURRENCY"
	envMaxValidateTimeout               = "BPFCOMPAT_API_MAX_VALIDATE_TIMEOUT"
	envMaxValidateProfiles              = "BPFCOMPAT_API_MAX_VALIDATE_PROFILES"
	envSourceCompileTimeout             = "BPFCOMPAT_API_SOURCE_COMPILE_TIMEOUT"
	envSourceCompileAllowExtraFlags     = "BPFCOMPAT_API_SOURCE_COMPILE_ALLOW_EXTRA_FLAGS"
	envAllowAnonymousRead               = "BPFCOMPAT_API_ALLOW_ANONYMOUS_READ"

	headerAPIKey           = "X-API-Key"
	headerIdentityToken    = "X-API-Identity-Token"
	headerExecApprove      = "X-Execute-Approval-Token"
	headerExecApprovedBy   = "X-Execute-Approved-By"
	defaultRuntimeFetchDir = "artifacts/runtime-selected"
)

var apiProfileIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var apiAllowedClangFlagPattern = regexp.MustCompile(`^(-D[A-Za-z_][A-Za-z0-9_]*(=.*)?|-U[A-Za-z_][A-Za-z0-9_]*)$`)
var apiSafeUploadFileNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
var apiAbsolutePathPattern = regexp.MustCompile(`(/[A-Za-z0-9._-]+)+`)

type Config struct {
	Addr               string
	WorkDir            string
	DefaultMatrixPath  string
	DefaultConcurrency int
	DefaultTimeout     time.Duration
	// TLSCertPath and TLSKeyPath enable HTTPS listening. Both must be set
	// together. When empty, the server falls back to plain HTTP and the
	// HSTS response header is suppressed so we don't mislead clients about
	// the actual transport security.
	TLSCertPath string
	TLSKeyPath  string
}

type Server struct {
	cfg          Config
	validateJobs validateJobStore
	runValidate  func(context.Context, runner.Config) (runner.RunResult, error)
	// logger is per-server so tests can inject a sink. Initialized lazily
	// from newDefaultLogger when nil.
	logger *slog.Logger
	// inflight tracks every async validate job goroutine so graceful
	// shutdown can wait for them before returning. Synchronous handlers
	// finish before httpServer.Shutdown returns; only the fire-and-forget
	// runValidateJob goroutines need explicit tracking.
	inflight sync.WaitGroup
	// shutting is set non-zero when Serve enters its shutdown sequence so
	// handlers can fast-fail new validate submissions instead of starting
	// a job that will be cancelled mid-flight. Plain int32 + atomic ops
	// avoids pulling in a sync.Once for what's effectively a flag.
	shutting atomicBool
}

func (s *Server) log() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}

func (s *Server) validateRunner() func(context.Context, runner.Config) (runner.RunResult, error) {
	if s.runValidate != nil {
		return s.runValidate
	}
	return runner.ExecuteBootstrap
}

// atomicBool is a tiny CAS-friendly flag. We have it inline to avoid pulling
// sync/atomic.Bool which is Go 1.19+ (we're 1.23 now, but keeping a custom
// type lets the field zero-value default to false without an init step).
type atomicBool struct {
	v   sync.Mutex
	set bool
}

func (a *atomicBool) Set(b bool) {
	a.v.Lock()
	a.set = b
	a.v.Unlock()
}

func (a *atomicBool) Get() bool {
	a.v.Lock()
	defer a.v.Unlock()
	return a.set
}

var runRuntimeExecuteWorkerFn = runRuntimeExecuteWorker

const maxStoredValidateJobs = 200

const (
	defaultMaxActiveValidateJobs  = 2
	defaultMaxQueuedValidateJobs  = 20
	defaultMaxValidateConcurrency = 8
	defaultMaxValidateProfiles    = 32
	defaultMaxValidateTimeout     = 15 * time.Minute
	defaultSourceCompileTimeout   = 30 * time.Second
)

type validateJobStore struct {
	mu   sync.RWMutex
	jobs map[string]*validateJob
}

type validateJob struct {
	JobID             string
	State             string
	Stage             string
	Message           string
	Percent           int
	TotalProfiles     int
	CompletedProfiles int
	ProfileStatusByID map[string]string
	StartedAt         time.Time
	UpdatedAt         time.Time
	FinishedAt        time.Time
	Response          *validateResponse
	Error             string
}

type apiConfigResponse struct {
	WriteAPIKeyConfigured         bool `json:"write_api_key_configured"`
	WriteIdentityVerifierEnabled  bool `json:"write_identity_verifier_enabled"`
	WriteRequireIdentity          bool `json:"write_require_identity"`
	AllowAnonymousValidate        bool `json:"allow_anonymous_validate"`
	AllowAnonymousWrite           bool `json:"allow_anonymous_write"`
	AllowAnonymousRuntimeDelivery bool `json:"allow_anonymous_runtime_delivery"`
	RegistryRequireIdentity       bool `json:"registry_require_identity"`
	RuntimeExecuteEnabled         bool `json:"runtime_execute_enabled"`
	RuntimeExecuteKillSwitch      bool `json:"runtime_execute_kill_switch"`
	RuntimeExecuteApprovalConfig  bool `json:"runtime_execute_approval_configured"`
}

type profileInfo struct {
	ID                 string `json:"id"`
	Distro             string `json:"distro"`
	Version            string `json:"version"`
	KernelFamily       string `json:"kernel_family"`
	Arch               string `json:"arch"`
	RequiredDefault    bool   `json:"required_default"`
	ImageLocalPath     string `json:"image_local_path"`
	ImageCached        bool   `json:"image_cached"`
	SourceMode         string `json:"source_mode"`
	SourceURL          string `json:"source_url,omitempty"`
	Transport          string `json:"transport"`
	TransportSupported bool   `json:"transport_supported"`
	TransportNote      string `json:"transport_note,omitempty"`
}

type compareRequest struct {
	BaseReport   string `json:"base_report"`
	HeadReport   string `json:"head_report"`
	ArtifactName string `json:"artifact_name"`
	BaseVersion  string `json:"base_version"`
	HeadVersion  string `json:"head_version"`
}

type runtimeSelectRequest struct {
	ArtifactName  string                        `json:"artifact_name"`
	Version       string                        `json:"version"`
	TargetProfile string                        `json:"target_profile"`
	Limit         int                           `json:"limit"`
	WorkDir       string                        `json:"workdir,omitempty"`
	Policy        runtimeSelectionPolicyRequest `json:"policy,omitempty"`
	Probe         runtimeProbeOptionsRequest    `json:"probe,omitempty"`
}

type runtimeFetchRequest struct {
	ArtifactName           string                        `json:"artifact_name"`
	Version                string                        `json:"version"`
	TargetProfile          string                        `json:"target_profile"`
	OutDir                 string                        `json:"out_dir"`
	WorkDir                string                        `json:"workdir,omitempty"`
	RequireVerifiedHistory *bool                         `json:"require_verified_history,omitempty"`
	Policy                 runtimeSelectionPolicyRequest `json:"policy,omitempty"`
	Probe                  runtimeProbeOptionsRequest    `json:"probe,omitempty"`
}

type runtimeProbeOptionsRequest struct {
	PreferPrivileged   bool  `json:"prefer_privileged,omitempty"`
	UseSudo            *bool `json:"use_sudo,omitempty"`
	SudoNonInteractive *bool `json:"sudo_non_interactive,omitempty"`
}

type runtimeSelectionPolicyRequest struct {
	RequireSummaryPass           bool     `json:"require_summary_pass,omitempty"`
	MinRequiredPassed            int      `json:"min_required_passed,omitempty"`
	MaxRequiredFailed            *int     `json:"max_required_failed,omitempty"`
	RequireKernelBTF             bool     `json:"require_kernel_btf,omitempty"`
	RequireAttachSupport         bool     `json:"require_attach_support,omitempty"`
	RequireRingbufSupport        bool     `json:"require_ringbuf_support,omitempty"`
	RequirePerfEventArraySupport bool     `json:"require_perf_event_array_support,omitempty"`
	DenyClassificationCodes      []string `json:"deny_classification_codes,omitempty"`
	AllowClassificationCodes     []string `json:"allow_classification_codes,omitempty"`
}

type runtimeExecuteRequest struct {
	Tenant                 string                        `json:"tenant"`
	Project                string                        `json:"project"`
	ArtifactName           string                        `json:"artifact_name"`
	Version                string                        `json:"version"`
	TargetProfile          string                        `json:"target_profile"`
	OutDir                 string                        `json:"out_dir"`
	WorkDir                string                        `json:"workdir,omitempty"`
	RequireVerifiedHistory *bool                         `json:"require_verified_history,omitempty"`
	ManifestPath           string                        `json:"manifest_path,omitempty"`
	AttachMode             string                        `json:"attach_mode,omitempty"`
	ProbeFeatures          *bool                         `json:"probe_features,omitempty"`
	AllowHostLoad          bool                          `json:"allow_host_load"`
	UseSudo                *bool                         `json:"use_sudo,omitempty"`
	SudoNonInteractive     *bool                         `json:"sudo_non_interactive,omitempty"`
	ValidatorPath          string                        `json:"validator_path,omitempty"`
	Timeout                string                        `json:"timeout,omitempty"`
	Policy                 runtimeSelectionPolicyRequest `json:"policy,omitempty"`
	Probe                  runtimeProbeOptionsRequest    `json:"probe,omitempty"`
}

type agentDecisionRequest struct {
	Tenant                 string                        `json:"tenant"`
	Project                string                        `json:"project"`
	AgentID                string                        `json:"agent_id,omitempty"`
	ArtifactName           string                        `json:"artifact_name"`
	Version                string                        `json:"version,omitempty"`
	TargetProfile          string                        `json:"target_profile,omitempty"`
	Limit                  int                           `json:"limit,omitempty"`
	RequireVerifiedHistory *bool                         `json:"require_verified_history,omitempty"`
	Policy                 runtimeSelectionPolicyRequest `json:"policy,omitempty"`
	HostProbe              runtime.HostCapabilities      `json:"host_probe"`
}

type validateResponse struct {
	ExitCode           int         `json:"exit_code"`
	RunDir             string      `json:"run_dir"`
	ReportJSONPath     string      `json:"report_json_path"`
	ReportMarkdownPath string      `json:"report_markdown_path,omitempty"`
	Report             interface{} `json:"report"`
}

type validateStartResponse struct {
	JobID     string `json:"job_id"`
	StatusURL string `json:"status_url"`
}

type validateStatusResponse struct {
	JobID             string            `json:"job_id"`
	State             string            `json:"state"`
	Stage             string            `json:"stage,omitempty"`
	Message           string            `json:"message,omitempty"`
	Percent           int               `json:"percent"`
	TotalProfiles     int               `json:"total_profiles,omitempty"`
	CompletedProfiles int               `json:"completed_profiles,omitempty"`
	ProfileStatuses   map[string]string `json:"profile_statuses,omitempty"`
	StartedAt         string            `json:"started_at,omitempty"`
	UpdatedAt         string            `json:"updated_at,omitempty"`
	FinishedAt        string            `json:"finished_at,omitempty"`
	Result            *validateResponse `json:"result,omitempty"`
	Error             string            `json:"error,omitempty"`
}

type registryProjectRequest struct {
	Tenant            string `json:"tenant"`
	Project           string `json:"project"`
	Visibility        string `json:"visibility,omitempty"`
	DefaultMatrixPath string `json:"default_matrix_path,omitempty"`
}

func (p runtimeSelectionPolicyRequest) toRuntimePolicy() runtime.SelectionPolicy {
	return runtime.SelectionPolicy{
		RequireSummaryPass:           p.RequireSummaryPass,
		MinRequiredPassed:            p.MinRequiredPassed,
		MaxRequiredFailed:            p.MaxRequiredFailed,
		RequireKernelBTF:             p.RequireKernelBTF,
		RequireAttachSupport:         p.RequireAttachSupport,
		RequireRingbufSupport:        p.RequireRingbufSupport,
		RequirePerfEventArraySupport: p.RequirePerfEventArraySupport,
		DenyClassificationCodes:      p.DenyClassificationCodes,
		AllowClassificationCodes:     p.AllowClassificationCodes,
	}
}

func (p runtimeSelectionPolicyRequest) validate() error {
	if p.MaxRequiredFailed != nil && *p.MaxRequiredFailed < 0 {
		return fmt.Errorf("policy.max_required_failed must be >= 0")
	}
	return nil
}

func (p runtimeProbeOptionsRequest) toRuntimeProbeOptions() runtime.ProbeOptions {
	useSudo := true
	if p.UseSudo != nil {
		useSudo = *p.UseSudo
	}
	sudoNonInteractive := true
	if p.SudoNonInteractive != nil {
		sudoNonInteractive = *p.SudoNonInteractive
	}
	return runtime.ProbeOptions{
		PreferPrivileged:   p.PreferPrivileged,
		UseSudo:            useSudo,
		SudoNonInteractive: sudoNonInteractive,
	}
}

func runtimePolicyTrace(policy runtime.SelectionPolicy) *runtime.SelectionPolicy {
	if !runtime.PolicyHasConstraints(policy) {
		return nil
	}
	policyCopy := policy
	return &policyCopy
}

func attachRuntimeAudit(resp map[string]any, workDir string, trace runtime.DecisionTrace) {
	audit, err := runtime.PersistDecisionTrace(workDir, trace)
	if err != nil {
		resp["audit_error"] = err.Error()
		return
	}
	resp["audit"] = audit
}

func Serve(ctx context.Context, cfg Config) error {
	if strings.TrimSpace(cfg.Addr) == "" {
		cfg.Addr = defaultAddr
	}
	if strings.TrimSpace(cfg.WorkDir) == "" {
		cfg.WorkDir = ".bpfcompat"
	}
	if cfg.DefaultConcurrency <= 0 {
		cfg.DefaultConcurrency = defaultConcurrency
	}
	if cfg.DefaultTimeout <= 0 {
		cfg.DefaultTimeout = defaultTimeout
	}

	server := &Server{cfg: cfg, logger: newDefaultLogger()}
	return server.serve(ctx)
}

func (s *Server) tlsEnabled() bool {
	return strings.TrimSpace(s.cfg.TLSCertPath) != "" && strings.TrimSpace(s.cfg.TLSKeyPath) != ""
}

// shutdownDrainTimeout returns the configured maximum wait for inflight
// validate jobs during graceful shutdown. Operators tune via env when their
// average job runtime is unusual.
func (s *Server) shutdownDrainTimeout() time.Duration {
	return parseBoundedDurationEnv(envShutdownDrainTimeout, defaultShutdownDrainTimeout, time.Second, 6*time.Hour)
}

// registerAPIRoute installs the handler under both the versioned
// "/api/v1/<route>" path (canonical) and the legacy "/api/<route>" path so
// existing clients keep working. The legacy alias is slated for removal in
// a future minor release; any new route added through this helper will
// follow the same v1+legacy pattern automatically.
func registerAPIRoute(mux *http.ServeMux, route string, handler func(http.ResponseWriter, *http.Request)) {
	canonical := "/api/v1" + route
	legacy := "/api" + route
	mux.HandleFunc(canonical, handler)
	mux.HandleFunc(legacy, handler)
}

func (s *Server) serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	// /livez and /readyz follow the Kubernetes probe conventions so the same
	// manifest can run in k8s without bespoke wrappers. They live outside
	// /api/ on purpose: they're infrastructure-level probes, never gated by
	// auth, and never logged at INFO (the access log middleware will still
	// record them, but most ops folk filter them out).
	mux.HandleFunc("/livez", s.handleLivez)
	mux.HandleFunc("/readyz", s.handleReadyz)

	// API routes register at /api/v1/<route> as the canonical home and ALSO
	// at the bare /api/<route> path so the existing demo UI, action.yml, and
	// integration tests keep working while clients migrate. The legacy alias
	// will be removed in a future minor release; new integrations should use
	// the versioned path. registerAPIRoute is a tiny helper that keeps the
	// two registrations in lockstep so adding a route can't accidentally
	// only land at one URL.
	registerAPIRoute(mux, "/health", s.handleHealth)
	registerAPIRoute(mux, "/config", s.handleConfig)
	registerAPIRoute(mux, "/profiles", s.handleProfiles)
	registerAPIRoute(mux, "/sample/aegis/artifact", s.handleSampleArtifact)
	registerAPIRoute(mux, "/validate/start", s.handleValidateStart)
	registerAPIRoute(mux, "/validate/status", s.handleValidateStatus)
	registerAPIRoute(mux, "/validate", s.handleValidate)
	registerAPIRoute(mux, "/history/artifacts", s.handleHistoryArtifacts)
	registerAPIRoute(mux, "/history/runs", s.handleHistoryRuns)
	registerAPIRoute(mux, "/history/run-report", s.handleRunReport)
	registerAPIRoute(mux, "/compare", s.handleCompare)
	registerAPIRoute(mux, "/runtime/probe", s.handleRuntimeProbe)
	registerAPIRoute(mux, "/runtime/decisions", s.handleRuntimeDecisions)
	registerAPIRoute(mux, "/runtime/select", s.handleRuntimeSelect)
	registerAPIRoute(mux, "/runtime/fetch", s.handleRuntimeFetch)
	registerAPIRoute(mux, "/runtime/execute", s.handleRuntimeExecute)
	registerAPIRoute(mux, "/agent/decision", s.handleAgentDecision)
	registerAPIRoute(mux, "/registry/projects", s.handleRegistryProjects)
	registerAPIRoute(mux, "/registry/artifacts/upload", s.handleRegistryArtifactUpload)
	registerAPIRoute(mux, "/registry/artifacts", s.handleRegistryArtifacts)
	registerAPIRoute(mux, "/registry/artifacts/download", s.handleRegistryArtifactDownload)
	registerAPIRoute(mux, "/registry/history/verify", s.handleRegistryHistoryVerify)
	registerAPIRoute(mux, "/registry/audit/events", s.handleRegistryAuditEvents)
	// Serve the OpenAPI document so clients can autogenerate bindings from
	// a stable URL on the deployed server, not the repo. Embedded at build
	// time so we don't depend on the file existing on disk in container
	// installs.
	mux.HandleFunc("/api/openapi.yaml", handleOpenAPISpec)
	mux.HandleFunc("/api/v1/openapi.yaml", handleOpenAPISpec)
	mux.HandleFunc("/results", s.handleDemoResult)
	mux.HandleFunc("/demo-result", s.handleDemoResult)
	if metricsEnabled() {
		mux.Handle("/metrics", s.handleMetrics())
	}
	// Runtime profiling: off by default. When the operator flips
	// BPFCOMPAT_API_ENABLE_PPROF on, /debug/pprof/* serves the standard Go
	// runtime profiles behind strict API-key/JWT auth. Anonymous demo modes
	// never open this endpoint. We mount the handler at the prefix so the
	// index page's relative links resolve.
	if pprofEnabled() {
		mux.Handle("/debug/pprof/", s.handlePprof())
	}

	tlsOn := s.tlsEnabled()
	// Middleware order (outermost first): security headers → request logging
	// → metrics → mux. Metrics sits inside logging so the request_id propagates
	// to logs and the counter increments for the same request; security
	// headers wraps everything so headers land even on logged 5xx responses.
	handler := withMetrics(mux)
	handler = withRequestLogging(handler, s.log())
	handler = withSecurityHeaders(handler, tlsOn)
	tlsCfg, err := tlsConfigForServer()
	if err != nil {
		return fmt.Errorf("build server TLS config: %w", err)
	}
	// Reject the silent-downgrade footgun: mTLS only makes sense over TLS.
	// If the operator configured a client CA but forgot to set cert/key,
	// fail loudly rather than serving plain HTTP without the client check.
	if clientCAEnabled() && !tlsOn {
		return fmt.Errorf("%s is set but TLS is not enabled; configure TLSCertPath/TLSKeyPath or unset the client CA", envClientCAPath)
	}
	httpServer := &http.Server{
		Addr:    s.cfg.Addr,
		Handler: handler,
		// Production hardening: bound every wait point so a slow or hostile
		// client can't park resources. WriteTimeout is deliberately left at
		// zero so long-running validate jobs that stream progress aren't cut
		// off — request bodies are bounded by ReadTimeout instead.
		ReadHeaderTimeout: httpServerReadHeaderTimeout,
		ReadTimeout:       httpServerReadTimeout,
		IdleTimeout:       httpServerIdleTimeout,
		MaxHeaderBytes:    httpServerMaxHeaderBytes,
		TLSConfig:         tlsCfg,
	}

	go func() {
		<-ctx.Done()
		s.shutting.Set(true)
		s.log().Info("shutdown signal received, draining inflight jobs",
			slog.Duration("drain_timeout", s.shutdownDrainTimeout()),
		)
		// Stop accepting new connections first so the inflight set stops
		// growing. Shutdown blocks until in-flight HTTP handlers return —
		// for our shape that's everything except the async runValidateJob
		// goroutines, which are tracked separately via s.inflight.
		httpShutdownCtx, cancelHTTP := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancelHTTP()
		_ = httpServer.Shutdown(httpShutdownCtx)
		// Now wait for the fire-and-forget validate jobs. The drain is
		// bounded so a stuck job can't hold the process open forever — a
		// rolling deploy will SIGKILL on overrun anyway, but the bounded
		// wait gives operators a clean exit when jobs do finish in time.
		drainCtx, cancelDrain := context.WithTimeout(context.Background(), s.shutdownDrainTimeout())
		defer cancelDrain()
		done := make(chan struct{})
		go func() {
			s.inflight.Wait()
			close(done)
		}()
		select {
		case <-done:
			s.log().Info("shutdown drain complete; all inflight jobs finished")
		case <-drainCtx.Done():
			s.log().Warn("shutdown drain timed out; remaining jobs will be terminated by exit",
				slog.Duration("drain_timeout", s.shutdownDrainTimeout()),
			)
		}
	}()

	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	listenURL := fmt.Sprintf("%s://%s", scheme, listenAddressForHumans(s.cfg.Addr))
	buildInfo := version.Resolve()
	s.log().Info("api server starting",
		slog.String("listen_url", listenURL),
		slog.String("addr", s.cfg.Addr),
		slog.Bool("tls", tlsOn),
		slog.String("workdir", s.cfg.WorkDir),
		slog.String("version", buildInfo.Version),
		slog.String("commit", buildInfo.Commit),
		slog.String("build_date", buildInfo.BuildDate),
	)
	// Preserve the human-readable startup line for operators tailing stdout
	// during a local run. Logs go to stderr via slog regardless.
	fmt.Printf("Web UI: %s\n", listenURL)

	if tlsOn {
		err = httpServer.ListenAndServeTLS(s.cfg.TLSCertPath, s.cfg.TLSKeyPath)
	} else {
		err = httpServer.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	nonce := generateCSPNonce(r)
	w.Header().Set("Content-Security-Policy", htmlCSPWithNonce(nonce))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, strings.ReplaceAll(uiHTML, "__CSP_NONCE__", nonce))
}

func generateCSPNonce(r *http.Request) string {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		// crypto/rand failures are effectively impossible on a healthy
		// host. If it does happen, fall back to a stable nonce derived from
		// the request ID so the page still loads (with a weaker guarantee).
		nonceBytes = []byte(requestIDFromContext(r.Context()))
	}
	return base64.StdEncoding.EncodeToString(nonceBytes)
}

func htmlCSPWithNonce(nonce string) string {
	return "default-src 'self'; img-src 'self' data:; " +
		"style-src 'self' 'nonce-" + nonce + "'; " +
		"script-src 'self' 'nonce-" + nonce + "'; " +
		"connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
}

// handleMetrics gates /metrics behind the same read-authorization helper
// used for other read endpoints. Scrapers must supply a valid API key /
// identity token unless anonymous read is explicitly enabled. Returning the
// wrapped Prometheus handler from a method lets us layer the auth check in
// without losing access to its content negotiation.
func (s *Server) handleMetrics() http.Handler {
	scrape := metricsHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if _, ok := requireReadAuthorizationForAction(w, r, "metrics"); !ok {
			return
		}
		scrape.ServeHTTP(w, r)
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	jwtCfg := writeJWTVerificationConfigFromEnv()
	resp := apiConfigResponse{
		WriteAPIKeyConfigured:         strings.TrimSpace(os.Getenv(envWriteAPIKey)) != "",
		WriteIdentityVerifierEnabled:  writeIdentityVerifierConfigured(jwtCfg),
		WriteRequireIdentity:          parseBoolEnv(envWriteRequireIdentity, false),
		AllowAnonymousValidate:        allowAnonymousValidateEnabled(),
		AllowAnonymousWrite:           allowAnonymousWriteEnabled(),
		AllowAnonymousRuntimeDelivery: allowAnonymousRuntimeDeliveryEnabled(),
		RegistryRequireIdentity:       parseBoolEnv(envRegistryRequireIdentity, false),
		RuntimeExecuteEnabled:         runtimeExecuteEnabled(),
		RuntimeExecuteKillSwitch:      runtimeExecuteKillSwitchEnabled(),
		RuntimeExecuteApprovalConfig:  strings.TrimSpace(os.Getenv(envRuntimeExecApprove)) != "",
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	profiles, err := s.listProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
}

func (s *Server) handleRuntimeProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireReadAuthorizationForAction(w, r, "runtime_probe"); !ok {
		return
	}
	probeOpts, err := parseRuntimeProbeOptionsQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	probe, err := runtime.ProbeHostCapabilitiesWithOptions(probeOpts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if redactRuntimeDetailsEnabled() {
		probe = sanitizeHostProbeForAPI(probe)
	}
	writeJSON(w, http.StatusOK, map[string]any{"probe": probe})
}

func (s *Server) handleRuntimeDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireReadAuthorizationForAction(w, r, "runtime_decisions"); !ok {
		return
	}
	limit := parseIntOrDefault(r.URL.Query().Get("limit"), 200)
	workDir := strings.TrimSpace(r.URL.Query().Get("workdir"))
	if workDir == "" {
		workDir = s.cfg.WorkDir
	}
	events, err := runtime.ListDecisionEvents(workDir, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("read runtime decision history: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": events})
}

func (s *Server) handleRuntimeSelect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireWriteAuthorizationForAction(w, r, "runtime_select"); !ok {
		return
	}

	var req runtimeSelectRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	artifactName := strings.TrimSpace(req.ArtifactName)
	if artifactName == "" {
		writeError(w, http.StatusBadRequest, "artifact_name is required")
		return
	}
	workDir := strings.TrimSpace(req.WorkDir)
	if workDir == "" {
		workDir = s.cfg.WorkDir
	}
	if err := req.Policy.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	policy := req.Policy.toRuntimePolicy()

	probeOpts := req.Probe.toRuntimeProbeOptions()
	host, err := runtime.ProbeHostCapabilitiesWithOptions(probeOpts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("runtime host probe failed: %v", err))
		return
	}
	records, err := registry.ListArtifactVersions(workDir, artifactName, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("read artifact history: %v", err))
		return
	}

	selection, err := runtime.SelectBestArtifactVersion(records, host, runtime.SelectionRequest{
		ArtifactName:     artifactName,
		RequestedVersion: strings.TrimSpace(req.Version),
		TargetProfileID:  strings.TrimSpace(req.TargetProfile),
		Limit:            req.Limit,
		Policy:           policy,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := map[string]any{
		"selection": selection,
	}
	if redactRuntimeDetailsEnabled() {
		host = sanitizeHostProbeForAPI(host)
	}
	attachRuntimeAudit(resp, workDir, runtime.DecisionTrace{
		Source:           "api",
		Operation:        "select",
		ArtifactName:     artifactName,
		RequestedVersion: strings.TrimSpace(req.Version),
		TargetProfileID:  strings.TrimSpace(req.TargetProfile),
		Policy:           runtimePolicyTrace(policy),
		Probe:            &probeOpts,
		HostProbe:        &host,
		Selection:        &selection,
		Status:           "success",
	})
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAgentDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req agentDecisionRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tenant := strings.TrimSpace(req.Tenant)
	projectID := strings.TrimSpace(req.Project)
	artifactName := strings.TrimSpace(req.ArtifactName)
	if tenant == "" || projectID == "" {
		writeError(w, http.StatusBadRequest, "tenant and project are required")
		return
	}
	if artifactName == "" {
		writeError(w, http.StatusBadRequest, "artifact_name is required")
		return
	}
	if strings.TrimSpace(req.HostProbe.SchemaVersion) == "" {
		writeError(w, http.StatusBadRequest, "host_probe is required")
		return
	}
	if err := req.Policy.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	store := cloudregistry.NewStore(s.cfg.WorkDir)
	if _, ok := requireRegistryIdentityForAction(w, r, "agent_decision", tenant, projectID); !ok {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:       "agent_decision",
			Tenant:       tenant,
			Project:      projectID,
			ArtifactName: artifactName,
			Status:       "denied",
			Message:      "registry identity denied",
			Metadata: map[string]any{
				"agent_id": strings.TrimSpace(req.AgentID),
			},
		})
		return
	}
	principal, err := store.AuthorizeToken(bearerToken(r), tenant, projectID, false)
	if err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:       "agent_decision",
			Tenant:       tenant,
			Project:      projectID,
			ArtifactName: artifactName,
			Status:       "denied",
			Message:      err.Error(),
			Metadata: map[string]any{
				"agent_id": strings.TrimSpace(req.AgentID),
			},
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}
	if err := enforceRegistryRateLimit(principal.Subject, tenant, projectID, "agent_decision"); err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:       "agent_decision",
			Actor:        actorFromPrincipal(principal, bearerToken(r)),
			Tenant:       tenant,
			Project:      projectID,
			ArtifactName: artifactName,
			Status:       "denied",
			Message:      err.Error(),
			Metadata: map[string]any{
				"agent_id": strings.TrimSpace(req.AgentID),
			},
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}

	records, err := store.ListArtifactVersions(tenant, projectID, artifactName, 0)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, cloudregistry.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, fmt.Sprintf("read artifact history: %v", err))
		return
	}

	projectWorkDir := registryProjectWorkDir(s.cfg.WorkDir, tenant, projectID)
	decision, selectedRecord, err := agent.BuildDecision(projectWorkDir, records, agent.DecisionRequest{
		Tenant:                 tenant,
		Project:                projectID,
		AgentID:                strings.TrimSpace(req.AgentID),
		ArtifactName:           artifactName,
		Version:                strings.TrimSpace(req.Version),
		TargetProfile:          strings.TrimSpace(req.TargetProfile),
		Limit:                  req.Limit,
		RequireVerifiedHistory: req.RequireVerifiedHistory,
		Policy:                 req.Policy.toRuntimePolicy(),
		HostProbe:              req.HostProbe,
	})
	if err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:       "agent_decision",
			Actor:        actorFromPrincipal(principal, bearerToken(r)),
			Tenant:       tenant,
			Project:      projectID,
			ArtifactName: artifactName,
			Status:       "denied",
			Message:      err.Error(),
			Metadata: map[string]any{
				"agent_id":          strings.TrimSpace(req.AgentID),
				"requested_version": strings.TrimSpace(req.Version),
				"target_profile":    strings.TrimSpace(req.TargetProfile),
			},
		})
		writeError(w, http.StatusPreconditionFailed, err.Error())
		return
	}
	downloadURL := registryArtifactDownloadURL(tenant, projectID, selectedRecord.ArtifactName, selectedRecord.ArtifactVersion)
	decision.SelectedArtifact = agent.SelectedArtifactFromRecord(selectedRecord, downloadURL)

	resp := map[string]any{
		"decision": decision,
	}
	trace := runtime.DecisionTrace{
		DecisionID:       decision.DecisionID,
		Source:           "agent",
		Operation:        "select",
		ArtifactName:     artifactName,
		RequestedVersion: strings.TrimSpace(req.Version),
		TargetProfileID:  strings.TrimSpace(req.TargetProfile),
		Policy:           runtimePolicyTrace(req.Policy.toRuntimePolicy()),
		HostProbe:        &req.HostProbe,
		Selection:        &decision.Selection,
		Status:           "success",
		Notes: []string{
			fmt.Sprintf("tenant/project: %s/%s", tenant, projectID),
			fmt.Sprintf("agent id: %s", strings.TrimSpace(req.AgentID)),
			"agent decision does not load on the API host",
		},
	}
	attachRuntimeAudit(resp, projectWorkDir, trace)
	appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
		Action:          "agent_decision",
		Actor:           actorFromPrincipal(principal, bearerToken(r)),
		Tenant:          tenant,
		Project:         projectID,
		ArtifactName:    artifactName,
		ArtifactVersion: selectedRecord.ArtifactVersion,
		Status:          "success",
		Metadata: map[string]any{
			"agent_id":          strings.TrimSpace(req.AgentID),
			"decision_id":       decision.DecisionID,
			"requested_version": strings.TrimSpace(req.Version),
			"target_profile":    strings.TrimSpace(req.TargetProfile),
			"artifact_sha256":   selectedRecord.ArtifactSHA256,
			"load_approved":     false,
		},
	})
	writeJSON(w, http.StatusOK, resp)
}

func registryArtifactDownloadURL(tenant, project, artifactName, version string) string {
	values := url.Values{}
	values.Set("tenant", strings.TrimSpace(tenant))
	values.Set("project", strings.TrimSpace(project))
	values.Set("artifact_name", strings.TrimSpace(artifactName))
	values.Set("version", strings.TrimSpace(version))
	return "/api/v1/registry/artifacts/download?" + values.Encode()
}

func (s *Server) handleRuntimeFetch(w http.ResponseWriter, r *http.Request) {
	outcome := "error"
	defer func() { recordRuntimeFetchOutcome(outcome) }()
	if r.Method != http.MethodPost {
		outcome = "method_not_allowed"
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireWriteAuthorizationForAction(w, r, "runtime_fetch"); !ok {
		outcome = "auth_denied"
		return
	}

	var req runtimeFetchRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	artifactName := strings.TrimSpace(req.ArtifactName)
	if artifactName == "" {
		writeError(w, http.StatusBadRequest, "artifact_name is required")
		return
	}
	workDir := strings.TrimSpace(req.WorkDir)
	if workDir == "" {
		workDir = s.cfg.WorkDir
	}
	outDir := strings.TrimSpace(req.OutDir)
	if outDir == "" {
		outDir = filepath.Join(workDir, defaultRuntimeFetchDir)
	}
	if err := req.Policy.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	policy := req.Policy.toRuntimePolicy()
	requireVerifiedHistory := true
	if req.RequireVerifiedHistory != nil {
		requireVerifiedHistory = *req.RequireVerifiedHistory
	}

	records, err := registry.ListArtifactVersions(workDir, artifactName, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("read artifact history: %v", err))
		return
	}

	var selectedRecord registry.ArtifactVersionRecord
	var selection *runtime.SelectionResult
	var hostProbe *runtime.HostCapabilities
	var probeOpts *runtime.ProbeOptions
	version := strings.TrimSpace(req.Version)
	if version != "" && !runtime.PolicyHasConstraints(policy) {
		selectedRecord, err = runtime.FindSelectedRecord(records, artifactName, version)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		opts := req.Probe.toRuntimeProbeOptions()
		host, err := runtime.ProbeHostCapabilitiesWithOptions(opts)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("runtime host probe failed: %v", err))
			return
		}
		probeOpts = &opts
		hostProbe = &host
		sel, err := runtime.SelectBestArtifactVersion(records, host, runtime.SelectionRequest{
			ArtifactName:     artifactName,
			RequestedVersion: version,
			TargetProfileID:  strings.TrimSpace(req.TargetProfile),
			Limit:            1,
			Policy:           policy,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		selection = &sel
		selectedRecord, err = runtime.FindSelectedRecord(records, artifactName, sel.Selected.ArtifactVersion)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("resolve selected record: %v", err))
			return
		}
	}

	var historyVerification *runtime.HistoryVerificationResult
	if requireVerifiedHistory {
		verification, err := runtime.VerifySelectedArtifactProvenance(workDir, selectedRecord)
		if err != nil {
			writeError(w, http.StatusPreconditionFailed, fmt.Sprintf("runtime history verification failed: %v", err))
			return
		}
		historyVerification = &verification
	}

	result, err := runtime.FetchArtifact(selectedRecord, outDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respFetch := result
	if redactRuntimeDetailsEnabled() {
		respFetch = sanitizeFetchResultForAPI(respFetch)
	}
	resp := map[string]any{
		"fetch": respFetch,
	}
	if selection != nil {
		resp["selection"] = selection
	}
	if hostProbe != nil {
		if redactRuntimeDetailsEnabled() {
			sanitized := sanitizeHostProbeForAPI(*hostProbe)
			resp["host_probe"] = sanitized
		} else {
			resp["host_probe"] = hostProbe
		}
	}
	if historyVerification != nil {
		resp["history_verification"] = historyVerification
	}
	trace := runtime.DecisionTrace{
		Source:           "api",
		Operation:        "fetch",
		ArtifactName:     artifactName,
		RequestedVersion: version,
		TargetProfileID:  strings.TrimSpace(req.TargetProfile),
		Policy:           runtimePolicyTrace(policy),
		Selection:        selection,
		Fetch:            &result,
		Status:           "success",
		Notes: []string{
			fmt.Sprintf("history verification required: %t", requireVerifiedHistory),
		},
	}
	if probeOpts != nil {
		trace.Probe = probeOpts
	}
	if hostProbe != nil {
		trace.HostProbe = hostProbe
	}
	attachRuntimeAudit(resp, workDir, trace)
	outcome = "success"
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRuntimeExecute(w http.ResponseWriter, r *http.Request) {
	outcome := "error"
	defer func() { recordRuntimeExecuteOutcome(outcome) }()
	if r.Method != http.MethodPost {
		outcome = "method_not_allowed"
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !runtimeExecuteEnabled() {
		outcome = "disabled"
		writeError(w, http.StatusForbidden, "runtime execute endpoint is disabled on this server")
		return
	}
	writeIdentity, ok := requireWriteAuthorizationForAction(w, r, "runtime_execute")
	if !ok {
		outcome = "auth_denied"
		return
	}
	approvedBy, requestedBy, ok := requireRuntimeExecuteApproval(w, r, writeIdentity)
	if !ok {
		outcome = "approval_denied"
		return
	}
	correlationID := shortID()

	var req runtimeExecuteRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	artifactName := strings.TrimSpace(req.ArtifactName)
	version := strings.TrimSpace(req.Version)
	targetProfile := strings.TrimSpace(req.TargetProfile)
	if artifactName == "" {
		writeError(w, http.StatusBadRequest, "artifact_name is required")
		return
	}
	if !req.AllowHostLoad {
		writeError(w, http.StatusBadRequest, "allow_host_load must be true for runtime execution")
		return
	}
	tenant := strings.TrimSpace(req.Tenant)
	projectID := strings.TrimSpace(req.Project)
	if tenant == "" || projectID == "" {
		writeError(w, http.StatusBadRequest, "tenant and project are required")
		return
	}
	if strings.TrimSpace(req.OutDir) != "" {
		writeError(w, http.StatusBadRequest, "out_dir override is not allowed for API runtime execute")
		return
	}
	if strings.TrimSpace(req.WorkDir) != "" {
		writeError(w, http.StatusBadRequest, "workdir override is not allowed for API runtime execute")
		return
	}
	if strings.TrimSpace(req.ManifestPath) != "" {
		writeError(w, http.StatusBadRequest, "manifest_path override is not allowed for API runtime execute")
		return
	}
	if strings.TrimSpace(req.ValidatorPath) != "" {
		writeError(w, http.StatusBadRequest, "validator_path override is not allowed for API runtime execute")
		return
	}
	if strings.TrimSpace(req.Timeout) != "" {
		writeError(w, http.StatusBadRequest, "timeout override is not allowed for API runtime execute")
		return
	}
	if req.UseSudo != nil || req.SudoNonInteractive != nil {
		writeError(w, http.StatusBadRequest, "sudo overrides are not allowed for API runtime execute")
		return
	}
	if req.RequireVerifiedHistory != nil && !*req.RequireVerifiedHistory {
		writeError(w, http.StatusBadRequest, "require_verified_history must be true for API runtime execute")
		return
	}
	if req.Probe.UseSudo != nil || req.Probe.SudoNonInteractive != nil {
		writeError(w, http.StatusBadRequest, "probe sudo overrides are not allowed for API runtime execute")
		return
	}

	workDir := s.cfg.WorkDir
	outDir := filepath.Join(workDir, defaultRuntimeFetchDir)
	if err := req.Policy.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	store := cloudregistry.NewStore(s.cfg.WorkDir)
	token := bearerToken(r)
	runtimeExecuteAuditMetadata := func(selectedVersion string, extra map[string]any) map[string]any {
		meta := map[string]any{
			"correlation_id":    correlationID,
			"approved_by":       approvedBy,
			"requested_by":      requestedBy,
			"requested_version": version,
			"target_profile":    targetProfile,
		}
		if selectedVersion != "" {
			meta["selected_version"] = selectedVersion
		}
		for k, v := range extra {
			if v == nil {
				continue
			}
			meta[k] = v
		}
		return meta
	}
	appendRuntimeExecuteDeniedAudit := func(actor, selectedVersion, message, reasonCode string, extra map[string]any) {
		meta := runtimeExecuteAuditMetadata(selectedVersion, extra)
		if reasonCode != "" {
			meta["deny_reason"] = reasonCode
		}
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:          "runtime_execute_denied",
			Actor:           actor,
			Tenant:          tenant,
			Project:         projectID,
			ArtifactName:    artifactName,
			ArtifactVersion: selectedVersion,
			Status:          "denied",
			Message:         message,
			Metadata:        meta,
		})
	}
	if err := enforceWriteIdentityTenantProject(writeIdentity, tenant, projectID); err != nil {
		appendRuntimeExecuteDeniedAudit(
			writeIdentitySubject(writeIdentity, r),
			version,
			err.Error(),
			"identity_scope_denied",
			map[string]any{"identity_auth_type": writeIdentity.AuthType},
		)
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	principal, err := store.AuthorizeToken(token, tenant, projectID, true)
	if err != nil {
		appendRuntimeExecuteDeniedAudit(tokenSubject(token), version, err.Error(), "registry_authorization_failed", nil)
		writeError(w, authzStatus(err), err.Error())
		return
	}
	if err := enforceRegistryRateLimit(principal.Subject, tenant, projectID, "runtime_execute"); err != nil {
		appendRuntimeExecuteDeniedAudit(actorFromPrincipal(principal, token), version, err.Error(), "rate_limited", nil)
		writeError(w, authzStatus(err), err.Error())
		return
	}
	policy := req.Policy.toRuntimePolicy()
	requireVerifiedHistory := true
	projectWorkDir := registryProjectWorkDir(s.cfg.WorkDir, tenant, projectID)
	runtimeGuardPolicy, guardPolicyErr := loadRuntimeExecuteGuardPolicyFromEnv()
	if guardPolicyErr != nil {
		message := fmt.Sprintf("runtime execute policy load failed: %v", guardPolicyErr)
		appendRuntimeExecuteDeniedAudit(
			actorFromPrincipal(principal, token),
			version,
			message,
			"policy_load_failed",
			map[string]any{"policy_path": strings.TrimSpace(os.Getenv(envRuntimeExecPolicyPath))},
		)
		writeError(w, http.StatusServiceUnavailable, message)
		return
	}
	if runtimeExecutePolicyRequired() && runtimeGuardPolicy == nil {
		message := fmt.Sprintf("runtime execute policy is required; set %s", envRuntimeExecPolicyPath)
		appendRuntimeExecuteDeniedAudit(
			actorFromPrincipal(principal, token),
			version,
			message,
			"policy_required_missing",
			map[string]any{"policy_required": true},
		)
		writeError(w, http.StatusServiceUnavailable, message)
		return
	}
	workerUser := runtimeExecuteWorkerUser()
	if runtimeExecuteRequireWorkerIdentity() && workerUser == "" {
		message := fmt.Sprintf("runtime execute worker identity is required; set %s", envRuntimeExecWorkerUser)
		appendRuntimeExecuteDeniedAudit(
			actorFromPrincipal(principal, token),
			version,
			message,
			"worker_identity_required",
			map[string]any{"worker_identity_required": true},
		)
		writeError(w, http.StatusServiceUnavailable, message)
		return
	}
	if runtimeExecuteKillSwitchEnabled() {
		outcome = "kill_switch"
		message := fmt.Sprintf("runtime execute is blocked by kill switch; unset %s to re-enable", envRuntimeExecKill)
		resp := map[string]any{
			"error":          message,
			"correlation_id": correlationID,
		}
		trace := runtime.DecisionTrace{
			DecisionID:       correlationID,
			Source:           "api",
			Operation:        "execute",
			ArtifactName:     artifactName,
			RequestedVersion: version,
			TargetProfileID:  targetProfile,
			Policy:           runtimePolicyTrace(policy),
			Status:           "denied",
			Error:            message,
			Notes: []string{
				fmt.Sprintf("correlation id: %s", correlationID),
				fmt.Sprintf("approved by: %s", approvedBy),
				fmt.Sprintf("requested by: %s", requestedBy),
				fmt.Sprintf("tenant/project: %s/%s", tenant, projectID),
			},
		}
		appendRuntimeExecuteDeniedAudit(
			actorFromPrincipal(principal, token),
			version,
			message,
			"kill_switch",
			map[string]any{"kill_switch_enabled": true},
		)
		attachRuntimeAudit(resp, workDir, trace)
		writeJSON(w, http.StatusServiceUnavailable, resp)
		return
	}

	records, err := store.ListArtifactVersions(tenant, projectID, artifactName, 0)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, cloudregistry.ErrNotFound) {
			status = http.StatusNotFound
		}
		message := fmt.Sprintf("read artifact history: %v", err)
		appendRuntimeExecuteDeniedAudit(actorFromPrincipal(principal, token), version, message, "history_read_failed", nil)
		writeError(w, status, message)
		return
	}

	var selectedRecord registry.ArtifactVersionRecord
	var selection *runtime.SelectionResult
	var hostProbe *runtime.HostCapabilities
	var probeOpts *runtime.ProbeOptions
	if version != "" && !runtime.PolicyHasConstraints(policy) {
		selectedRecord, err = store.ResolveArtifactVersion(tenant, projectID, artifactName, version)
		if err != nil {
			appendRuntimeExecuteDeniedAudit(
				actorFromPrincipal(principal, token),
				version,
				err.Error(),
				"version_resolution_failed",
				nil,
			)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		opts := runtime.ProbeOptions{
			PreferPrivileged:   false,
			UseSudo:            false,
			SudoNonInteractive: true,
		}
		probe, err := runtime.ProbeHostCapabilitiesWithOptions(opts)
		if err != nil {
			message := fmt.Sprintf("runtime host probe failed: %v", err)
			appendRuntimeExecuteDeniedAudit(actorFromPrincipal(principal, token), version, message, "host_probe_failed", nil)
			writeError(w, http.StatusInternalServerError, message)
			return
		}
		probeOpts = &opts
		hostProbe = &probe
		sel, err := runtime.SelectBestArtifactVersion(records, probe, runtime.SelectionRequest{
			ArtifactName:     artifactName,
			RequestedVersion: version,
			TargetProfileID:  targetProfile,
			Limit:            1,
			Policy:           policy,
		})
		if err != nil {
			appendRuntimeExecuteDeniedAudit(
				actorFromPrincipal(principal, token),
				version,
				err.Error(),
				"selection_failed",
				map[string]any{"selection_attempted": true},
			)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		selection = &sel
		selectedRecord, err = runtime.FindSelectedRecord(records, artifactName, sel.Selected.ArtifactVersion)
		if err != nil {
			message := fmt.Sprintf("resolve selected record: %v", err)
			appendRuntimeExecuteDeniedAudit(
				actorFromPrincipal(principal, token),
				version,
				message,
				"selected_record_resolution_failed",
				map[string]any{"selected_version": sel.Selected.ArtifactVersion},
			)
			writeError(w, http.StatusInternalServerError, message)
			return
		}
	}

	if runtimeGuardPolicy != nil && hostProbe == nil && runtimeExecutePolicyNeedsHostProbe(*runtimeGuardPolicy, targetProfile) {
		opts := runtime.ProbeOptions{
			PreferPrivileged:   false,
			UseSudo:            false,
			SudoNonInteractive: true,
		}
		probe, err := runtime.ProbeHostCapabilitiesWithOptions(opts)
		if err != nil {
			message := fmt.Sprintf("runtime host probe failed: %v", err)
			appendRuntimeExecuteDeniedAudit(
				actorFromPrincipal(principal, token),
				selectedRecord.ArtifactVersion,
				message,
				"host_probe_failed",
				nil,
			)
			writeError(w, http.StatusInternalServerError, message)
			return
		}
		probeOpts = &opts
		hostProbe = &probe
	}

	var historyVerification *runtime.HistoryVerificationResult
	if requireVerifiedHistory {
		verification, err := runtime.VerifySelectedArtifactProvenance(projectWorkDir, selectedRecord)
		if err != nil {
			message := fmt.Sprintf("runtime history verification failed: %v", err)
			appendRuntimeExecuteDeniedAudit(
				actorFromPrincipal(principal, token),
				selectedRecord.ArtifactVersion,
				message,
				"history_verification_failed",
				map[string]any{"require_verified_history": true},
			)
			writeError(w, http.StatusPreconditionFailed, message)
			return
		}
		historyVerification = &verification
	}

	var policyManifest *manifest.Manifest
	if runtimeGuardPolicy != nil && runtimeExecutePolicyNeedsManifest(*runtimeGuardPolicy) {
		manifestPath := strings.TrimSpace(selectedRecord.ManifestPath)
		if manifestPath == "" {
			message := "runtime execute policy requires manifest fields but selected artifact has no manifest_path"
			appendRuntimeExecuteDeniedAudit(
				actorFromPrincipal(principal, token),
				selectedRecord.ArtifactVersion,
				message,
				"policy_manifest_missing",
				nil,
			)
			writeError(w, http.StatusForbidden, message)
			return
		}
		safeManifestPath, err := resolveServerLocalManifestPath(s.cfg.WorkDir, manifestPath)
		if err != nil {
			message := "runtime execute policy manifest path is not server-local"
			appendRuntimeExecuteDeniedAudit(
				actorFromPrincipal(principal, token),
				selectedRecord.ArtifactVersion,
				message,
				"policy_manifest_path_unsafe",
				nil,
			)
			writeError(w, http.StatusForbidden, message)
			return
		}
		manifestPath = safeManifestPath
		m, err := manifest.Load(filepath.Clean(manifestPath))
		if err != nil {
			message := fmt.Sprintf("runtime execute policy manifest load failed: %v", err)
			appendRuntimeExecuteDeniedAudit(
				actorFromPrincipal(principal, token),
				selectedRecord.ArtifactVersion,
				message,
				"policy_manifest_load_failed",
				nil,
			)
			writeError(w, http.StatusForbidden, message)
			return
		}
		policyManifest = &m
	}

	policyDecisionRule := ""
	if runtimeGuardPolicy != nil {
		guardCtx := runtimeExecuteGuardContext{
			Tenant:          tenant,
			Project:         projectID,
			ArtifactName:    artifactName,
			TargetProfileID: targetProfile,
			SelectedRecord:  selectedRecord,
			HostProbe:       hostProbe,
			HistoryVerified: historyVerification != nil && historyVerification.Verified,
			Manifest:        policyManifest,
		}
		decision := evaluateRuntimeExecuteGuardPolicy(*runtimeGuardPolicy, guardCtx)
		policyDecisionRule = decision.RuleName + ":" + decision.Action
		if !decision.Allowed {
			message := fmt.Sprintf("runtime execute policy denied: %s", decision.Reason)
			resp := map[string]any{
				"error":          message,
				"correlation_id": correlationID,
				"policy":         map[string]any{"rule": decision.RuleName, "action": decision.Action, "reason": decision.Reason},
			}
			trace := runtime.DecisionTrace{
				DecisionID:       correlationID,
				Source:           "api",
				Operation:        "execute",
				ArtifactName:     artifactName,
				RequestedVersion: version,
				TargetProfileID:  targetProfile,
				Policy:           runtimePolicyTrace(policy),
				Selection:        selection,
				Status:           "denied",
				Error:            message,
				Notes: []string{
					fmt.Sprintf("correlation id: %s", correlationID),
					fmt.Sprintf("approved by: %s", approvedBy),
					fmt.Sprintf("requested by: %s", requestedBy),
					fmt.Sprintf("tenant/project: %s/%s", tenant, projectID),
					fmt.Sprintf("policy decision: %s", policyDecisionRule),
				},
			}
			if hostProbe != nil {
				trace.HostProbe = hostProbe
			}
			if probeOpts != nil {
				trace.Probe = probeOpts
			}
			appendRuntimeExecuteDeniedAudit(
				actorFromPrincipal(principal, token),
				selectedRecord.ArtifactVersion,
				message,
				"policy_denied",
				map[string]any{
					"policy_rule":   decision.RuleName,
					"policy_action": decision.Action,
					"policy_reason": decision.Reason,
				},
			)
			attachRuntimeAudit(resp, workDir, trace)
			writeJSON(w, http.StatusForbidden, resp)
			return
		}
	}

	fetched, err := runtime.FetchArtifact(selectedRecord, outDir)
	if err != nil {
		message := fmt.Sprintf("runtime fetch failed: %v", err)
		appendRuntimeExecuteDeniedAudit(
			actorFromPrincipal(principal, token),
			selectedRecord.ArtifactVersion,
			message,
			"fetch_failed",
			nil,
		)
		writeError(w, http.StatusInternalServerError, message)
		return
	}

	manifestPath := strings.TrimSpace(selectedRecord.ManifestPath)
	if manifestPath != "" {
		safeManifestPath, err := resolveServerLocalManifestPath(s.cfg.WorkDir, manifestPath)
		if err != nil {
			// Stored manifest_path is not server-local. Drop it rather than
			// hand it to the validator under sudo; the artifact still runs,
			// it just won't have manifest-driven attach hints.
			manifestPath = ""
		} else {
			manifestPath = safeManifestPath
		}
	}

	timeout := 2 * time.Minute

	probeFeatures := true
	if req.ProbeFeatures != nil {
		probeFeatures = *req.ProbeFeatures
	}

	execution, err := runRuntimeExecuteWorkerFn(r.Context(), runtime.ExecuteRequest{
		ArtifactPath:        fetched.OutputPath,
		ManifestPath:        manifestPath,
		AttachMode:          strings.TrimSpace(req.AttachMode),
		ProbeFeatures:       probeFeatures,
		AllowHostLoad:       req.AllowHostLoad,
		UseSudo:             true,
		SudoNonInteractive:  true,
		ValidatorBinaryPath: "",
		WorkDir:             workDir,
		Timeout:             timeout,
	})
	if err != nil {
		message := fmt.Sprintf("runtime execute failed: %v", err)
		appendRuntimeExecuteDeniedAudit(
			actorFromPrincipal(principal, token),
			selectedRecord.ArtifactVersion,
			message,
			"worker_execution_failed",
			nil,
		)
		writeError(w, http.StatusInternalServerError, message)
		return
	}

	resp := map[string]any{
		"correlation_id": correlationID,
		"fetch":          fetched,
		"execution":      execution,
	}
	if redactRuntimeDetailsEnabled() {
		resp["fetch"] = sanitizeFetchResultForAPI(fetched)
		resp["execution"] = sanitizeExecuteResultForAPI(execution)
	}
	if selection != nil {
		resp["selection"] = selection
	}
	if hostProbe != nil {
		if redactRuntimeDetailsEnabled() {
			sanitized := sanitizeHostProbeForAPI(*hostProbe)
			resp["host_probe"] = sanitized
		} else {
			resp["host_probe"] = hostProbe
		}
	}
	if historyVerification != nil {
		resp["history_verification"] = historyVerification
	}
	trace := runtime.DecisionTrace{
		DecisionID:       correlationID,
		Source:           "api",
		Operation:        "execute",
		ArtifactName:     artifactName,
		RequestedVersion: version,
		TargetProfileID:  targetProfile,
		Policy:           runtimePolicyTrace(policy),
		Selection:        selection,
		Fetch:            &fetched,
		Execution:        &execution,
		Status:           "success",
		Notes: []string{
			fmt.Sprintf("correlation id: %s", correlationID),
			fmt.Sprintf("history verification required: %t", requireVerifiedHistory),
			fmt.Sprintf("approved by: %s", approvedBy),
			fmt.Sprintf("requested by: %s", requestedBy),
			fmt.Sprintf("tenant/project: %s/%s", tenant, projectID),
			fmt.Sprintf("worker identity: %s", runtimeExecuteWorkerIdentityLabel(workerUser)),
			"api execute uses fixed safe defaults (workdir/outdir/validator/sudo/timeout)",
		},
	}
	if policyDecisionRule != "" {
		trace.Notes = append(trace.Notes, fmt.Sprintf("policy decision: %s", policyDecisionRule))
	}
	if probeOpts != nil {
		trace.Probe = probeOpts
	}
	if hostProbe != nil {
		trace.HostProbe = hostProbe
	}
	attachRuntimeAudit(resp, workDir, trace)
	successAuditMetadata := map[string]any{
		"artifact_sha256":  selectedRecord.ArtifactSHA256,
		"execution_status": execution.Status,
		"worker_identity":  runtimeExecuteWorkerIdentityLabel(workerUser),
	}
	if policyDecisionRule != "" {
		successAuditMetadata["policy_result"] = policyDecisionRule
	}
	_, _ = store.AppendAudit(cloudregistry.AuditEvent{
		Action:          "runtime_execute",
		Actor:           actorFromPrincipal(principal, token),
		Tenant:          tenant,
		Project:         projectID,
		ArtifactName:    artifactName,
		ArtifactVersion: selectedRecord.ArtifactVersion,
		Status:          "success",
		Metadata:        runtimeExecuteAuditMetadata(selectedRecord.ArtifactVersion, successAuditMetadata),
	})
	outcome = "success"
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRegistryProjects(w http.ResponseWriter, r *http.Request) {
	store := cloudregistry.NewStore(s.cfg.WorkDir)
	switch r.Method {
	case http.MethodGet:
		tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
		projectID := strings.TrimSpace(r.URL.Query().Get("project"))
		if tenant == "" {
			writeError(w, http.StatusBadRequest, "tenant is required")
			return
		}

		token := bearerToken(r)
		if projectID != "" {
			if _, ok := requireRegistryIdentityForAction(w, r, "registry_project_read", tenant, projectID); !ok {
				return
			}
			principal, err := store.AuthorizeRead(token, tenant, projectID)
			if err != nil {
				appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
					Action:  "project_read_denied",
					Actor:   tokenSubject(token),
					Tenant:  tenant,
					Project: projectID,
					Status:  "denied",
					Message: err.Error(),
				})
				writeError(w, authzStatus(err), err.Error())
				return
			}
			if err := enforceRegistryRateLimit(principal.Subject, tenant, projectID, "project_read"); err != nil {
				appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
					Action:  "project_read_denied",
					Actor:   actorFromPrincipal(principal, token),
					Tenant:  tenant,
					Project: projectID,
					Status:  "denied",
					Message: err.Error(),
				})
				writeError(w, authzStatus(err), err.Error())
				return
			}
			project, err := store.GetProject(tenant, projectID)
			if err != nil {
				status := http.StatusInternalServerError
				if errors.Is(err, cloudregistry.ErrNotFound) {
					status = http.StatusNotFound
				}
				writeError(w, status, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"projects": []cloudregistry.Project{project}})
			return
		}

		if _, ok := requireRegistryIdentityForAction(w, r, "registry_project_list", tenant, ""); !ok {
			return
		}
		principal, err := store.AuthorizeToken(token, tenant, "", false)
		if err != nil {
			appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
				Action:  "project_list_denied",
				Actor:   tokenSubject(token),
				Tenant:  tenant,
				Status:  "denied",
				Message: err.Error(),
			})
			writeError(w, authzStatus(err), err.Error())
			return
		}
		if err := enforceRegistryRateLimit(principal.Subject, tenant, "", "project_list"); err != nil {
			appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
				Action:  "project_list_denied",
				Actor:   actorFromPrincipal(principal, token),
				Tenant:  tenant,
				Status:  "denied",
				Message: err.Error(),
			})
			writeError(w, authzStatus(err), err.Error())
			return
		}
		limit := parseIntOrDefault(r.URL.Query().Get("limit"), 200)
		projects, err := store.ListProjects(tenant, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
	case http.MethodPost:
		var req registryProjectRequest
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		token := bearerToken(r)
		reqTenant := strings.TrimSpace(req.Tenant)
		reqProject := strings.TrimSpace(req.Project)
		if _, ok := requireRegistryIdentityForAction(w, r, "registry_project_upsert", reqTenant, reqProject); !ok {
			return
		}
		principal, err := store.AuthorizeToken(token, reqTenant, reqProject, true)
		if err != nil {
			appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
				Action:  "project_upsert_denied",
				Actor:   tokenSubject(token),
				Tenant:  reqTenant,
				Project: reqProject,
				Status:  "denied",
				Message: err.Error(),
			})
			writeError(w, authzStatus(err), err.Error())
			return
		}
		if err := enforceRegistryRateLimit(principal.Subject, reqTenant, reqProject, "project_upsert"); err != nil {
			appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
				Action:  "project_upsert_denied",
				Actor:   actorFromPrincipal(principal, token),
				Tenant:  reqTenant,
				Project: reqProject,
				Status:  "denied",
				Message: err.Error(),
			})
			writeError(w, authzStatus(err), err.Error())
			return
		}
		project, err := store.UpsertProject(cloudregistry.CreateProjectInput{
			Tenant:            reqTenant,
			Project:           reqProject,
			Visibility:        strings.TrimSpace(req.Visibility),
			DefaultMatrixPath: strings.TrimSpace(req.DefaultMatrixPath),
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		_, _ = store.AppendAudit(cloudregistry.AuditEvent{
			Action:  "project_upsert",
			Actor:   actorFromPrincipal(principal, token),
			Tenant:  project.Tenant,
			Project: project.Project,
			Status:  "success",
		})
		writeJSON(w, http.StatusOK, map[string]any{"project": project})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleRegistryArtifactUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := r.ParseMultipartForm(maxMultipartFormBytes); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("parse multipart form: %v", err))
		return
	}
	tenant := strings.TrimSpace(r.FormValue("tenant"))
	projectID := strings.TrimSpace(r.FormValue("project"))
	artifactName := strings.TrimSpace(r.FormValue("artifact_name"))
	artifactVersion := strings.TrimSpace(r.FormValue("artifact_version"))
	artifactVariant := strings.TrimSpace(r.FormValue("artifact_variant"))

	store := cloudregistry.NewStore(s.cfg.WorkDir)
	if _, ok := requireRegistryIdentityForAction(w, r, "registry_artifact_upload", tenant, projectID); !ok {
		return
	}
	token := bearerToken(r)
	principal, err := store.AuthorizeToken(token, tenant, projectID, true)
	if err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:  "artifact_upload_denied",
			Actor:   tokenSubject(token),
			Tenant:  tenant,
			Project: projectID,
			Status:  "denied",
			Message: err.Error(),
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}
	if err := enforceRegistryRateLimit(principal.Subject, tenant, projectID, "artifact_upload"); err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:  "artifact_upload_denied",
			Actor:   actorFromPrincipal(principal, token),
			Tenant:  tenant,
			Project: projectID,
			Status:  "denied",
			Message: err.Error(),
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}

	artifactFile, _, err := r.FormFile("artifact_file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "artifact_file is required")
		return
	}
	defer artifactFile.Close()

	report, err := extractRegistryReport(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	compat := cloudregistry.CompatibilityMetadata{
		SummaryStatus:      strings.TrimSpace(r.FormValue("summary_status")),
		RequiredPassed:     parseIntOrDefault(r.FormValue("required_passed"), 0),
		RequiredFailed:     parseIntOrDefault(r.FormValue("required_failed"), 0),
		TotalProfiles:      parseIntOrDefault(r.FormValue("total_profiles"), 0),
		MatrixPath:         strings.TrimSpace(r.FormValue("matrix_path")),
		MatrixName:         strings.TrimSpace(r.FormValue("matrix_name")),
		MarkdownPath:       strings.TrimSpace(r.FormValue("markdown_path")),
		SupportedProfiles:  collectMultiValues(r.MultipartForm.Value["supported_profiles"]),
		FailedProfiles:     collectMultiValues(r.MultipartForm.Value["failed_profiles"]),
		ClassificationCode: collectMultiValues(r.MultipartForm.Value["classification_codes"]),
	}

	uploadResult, err := store.UploadArtifact(cloudregistry.UploadInput{
		Tenant:          tenant,
		Project:         projectID,
		ArtifactName:    artifactName,
		ArtifactVersion: artifactVersion,
		ArtifactVariant: artifactVariant,
		ArtifactURI:     strings.TrimSpace(r.FormValue("artifact_uri")),
		ManifestPath:    strings.TrimSpace(r.FormValue("manifest_path")),
		ExpectedSHA256:  strings.TrimSpace(r.FormValue("artifact_sha256")),
		SourceRunID:     strings.TrimSpace(r.FormValue("source_run_id")),
		ArtifactReader:  artifactFile,
		Compatibility:   compat,
		Report:          report,
	})
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, cloudregistry.ErrNotFound) {
			status = http.StatusNotFound
		}
		if errors.Is(err, cloudregistry.ErrConflict) {
			status = http.StatusConflict
		}
		if errors.Is(err, cloudregistry.ErrQuotaExceeded) {
			status = http.StatusTooManyRequests
		}
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:          "artifact_upload_denied",
			Actor:           actorFromPrincipal(principal, token),
			Tenant:          tenant,
			Project:         projectID,
			ArtifactName:    artifactName,
			ArtifactVersion: artifactVersion,
			Status:          "denied",
			Message:         err.Error(),
		})
		writeError(w, status, err.Error())
		return
	}

	downloadURI := fmt.Sprintf(
		"/api/registry/artifacts/download?tenant=%s&project=%s&artifact_name=%s&version=%s",
		tenant,
		projectID,
		artifactName,
		artifactVersion,
	)
	_, _ = store.AppendAudit(cloudregistry.AuditEvent{
		Action:          "artifact_upload",
		Actor:           actorFromPrincipal(principal, token),
		Tenant:          tenant,
		Project:         projectID,
		ArtifactName:    artifactName,
		ArtifactVersion: artifactVersion,
		Status:          "success",
		Metadata: map[string]any{
			"sha256": uploadResult.Record.ArtifactSHA256,
		},
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"result":       uploadResult,
		"download_uri": downloadURI,
	})
}

func (s *Server) handleRegistryArtifacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
	projectID := strings.TrimSpace(r.URL.Query().Get("project"))
	artifactName := strings.TrimSpace(r.URL.Query().Get("artifact_name"))
	limit := parseIntOrDefault(r.URL.Query().Get("limit"), 200)
	if tenant == "" || projectID == "" {
		writeError(w, http.StatusBadRequest, "tenant and project are required")
		return
	}

	store := cloudregistry.NewStore(s.cfg.WorkDir)
	if _, ok := requireRegistryIdentityForAction(w, r, "registry_artifact_list", tenant, projectID); !ok {
		return
	}
	token := bearerToken(r)
	principal, err := store.AuthorizeRead(token, tenant, projectID)
	if err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:  "artifact_list_denied",
			Actor:   tokenSubject(token),
			Tenant:  tenant,
			Project: projectID,
			Status:  "denied",
			Message: err.Error(),
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}
	if err := enforceRegistryRateLimit(principal.Subject, tenant, projectID, "artifact_list"); err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:  "artifact_list_denied",
			Actor:   actorFromPrincipal(principal, token),
			Tenant:  tenant,
			Project: projectID,
			Status:  "denied",
			Message: err.Error(),
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}

	records, err := store.ListArtifactVersions(tenant, projectID, artifactName, limit)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, cloudregistry.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

func (s *Server) handleRegistryArtifactDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
	projectID := strings.TrimSpace(r.URL.Query().Get("project"))
	artifactName := strings.TrimSpace(r.URL.Query().Get("artifact_name"))
	version := strings.TrimSpace(r.URL.Query().Get("version"))
	if tenant == "" || projectID == "" || artifactName == "" || version == "" {
		writeError(w, http.StatusBadRequest, "tenant, project, artifact_name, and version are required")
		return
	}

	store := cloudregistry.NewStore(s.cfg.WorkDir)
	if _, ok := requireRegistryIdentityForAction(w, r, "registry_artifact_download", tenant, projectID); !ok {
		return
	}
	token := bearerToken(r)
	principal, err := store.AuthorizeRead(token, tenant, projectID)
	if err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:          "artifact_download_denied",
			Actor:           tokenSubject(token),
			Tenant:          tenant,
			Project:         projectID,
			ArtifactName:    artifactName,
			ArtifactVersion: version,
			Status:          "denied",
			Message:         err.Error(),
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}
	if err := enforceRegistryRateLimit(principal.Subject, tenant, projectID, "artifact_download"); err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:          "artifact_download_denied",
			Actor:           actorFromPrincipal(principal, token),
			Tenant:          tenant,
			Project:         projectID,
			ArtifactName:    artifactName,
			ArtifactVersion: version,
			Status:          "denied",
			Message:         err.Error(),
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}

	record, err := store.ResolveArtifactVersion(tenant, projectID, artifactName, version)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, cloudregistry.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	f, err := os.Open(filepath.Clean(record.ArtifactPath))
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "artifact file not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("open artifact: %v", err))
		return
	}
	defer f.Close()

	fileName := fmt.Sprintf("%s-%s.bpf.o", artifactName, version)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	w.Header().Set("X-BPF-SHA256", record.ArtifactSHA256)
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		return
	}

	_, _ = store.AppendAudit(cloudregistry.AuditEvent{
		Action:          "artifact_download",
		Actor:           actorFromPrincipal(principal, token),
		Tenant:          tenant,
		Project:         projectID,
		ArtifactName:    artifactName,
		ArtifactVersion: version,
		Status:          "success",
	})
}

func (s *Server) handleRegistryHistoryVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
	projectID := strings.TrimSpace(r.URL.Query().Get("project"))
	if tenant == "" || projectID == "" {
		writeError(w, http.StatusBadRequest, "tenant and project are required")
		return
	}

	store := cloudregistry.NewStore(s.cfg.WorkDir)
	if _, ok := requireRegistryIdentityForAction(w, r, "registry_history_verify", tenant, projectID); !ok {
		return
	}
	token := bearerToken(r)
	principal, err := store.AuthorizeRead(token, tenant, projectID)
	if err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:  "history_verify_denied",
			Actor:   tokenSubject(token),
			Tenant:  tenant,
			Project: projectID,
			Status:  "denied",
			Message: err.Error(),
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}
	if err := enforceRegistryRateLimit(principal.Subject, tenant, projectID, "history_verify"); err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:  "history_verify_denied",
			Actor:   actorFromPrincipal(principal, token),
			Tenant:  tenant,
			Project: projectID,
			Status:  "denied",
			Message: err.Error(),
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}

	verification, err := store.VerifyHistory(tenant, projectID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, cloudregistry.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	failed := 0
	for _, row := range verification {
		if !row.Verified {
			failed++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"verification": verification,
		"summary": map[string]any{
			"total":  len(verification),
			"failed": failed,
		},
	})
}

func (s *Server) handleRegistryAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
	projectID := strings.TrimSpace(r.URL.Query().Get("project"))
	if tenant == "" {
		writeError(w, http.StatusBadRequest, "tenant is required")
		return
	}
	limit := parseIntOrDefault(r.URL.Query().Get("limit"), 200)
	token := bearerToken(r)
	store := cloudregistry.NewStore(s.cfg.WorkDir)
	if _, ok := requireRegistryIdentityForAction(w, r, "registry_audit_list", tenant, projectID); !ok {
		return
	}
	var (
		err       error
		principal cloudregistry.Principal
	)
	if projectID == "" {
		principal, err = store.AuthorizeToken(token, tenant, "", false)
	} else {
		principal, err = store.AuthorizeRead(token, tenant, projectID)
	}
	if err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:  "audit_list_denied",
			Actor:   tokenSubject(token),
			Tenant:  tenant,
			Project: projectID,
			Status:  "denied",
			Message: err.Error(),
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}
	if err := enforceRegistryRateLimit(principal.Subject, tenant, projectID, "audit_list"); err != nil {
		appendRegistryAuditBestEffort(store, cloudregistry.AuditEvent{
			Action:  "audit_list_denied",
			Actor:   actorFromPrincipal(principal, token),
			Tenant:  tenant,
			Project: projectID,
			Status:  "denied",
			Message: err.Error(),
		})
		writeError(w, authzStatus(err), err.Error())
		return
	}

	events, err := store.ListAuditEvents(tenant, projectID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": events})
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireWriteAuthorizationForAction(w, r, "validate"); !ok {
		return
	}
	cfg, status, err := s.buildValidateRunnerConfig(r)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}

	result, err := s.validateRunner()(r.Context(), cfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.autoSyncValidationArtifact(cfg, result); err != nil {
		s.log().Warn("auto-sync registry warning", slog.String("error", err.Error()))
	}

	response := validateResponse{
		ExitCode:           result.ExitCode,
		RunDir:             result.RunDir,
		ReportJSONPath:     result.Report.Paths.JSON,
		ReportMarkdownPath: result.Report.Paths.Markdown,
		Report:             result.Report,
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleValidateStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireWriteAuthorizationForAction(w, r, "validate"); !ok {
		return
	}
	// Refuse new long-running submissions once shutdown started. Returning
	// 503 here lets clients retry against a healthy replica during rolling
	// deploys; without this the goroutine would launch and immediately get
	// killed when httpServer.Shutdown's context expired.
	if s.shutting.Get() {
		writeError(w, http.StatusServiceUnavailable, "server is shutting down; retry shortly")
		return
	}

	cfg, status, err := s.buildValidateRunnerConfig(r)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	if err := s.ensureValidateJobCapacity(); err != nil {
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}

	profileIDs := []string{}
	if m, err := matrix.Load(cfg.MatrixPath); err == nil {
		profileIDs = m.ProfileIDs()
	}
	jobID := s.createValidateJob(profileIDs)
	cfg.Progress = func(update runner.ProgressUpdate) {
		s.applyRunnerProgress(jobID, update)
	}

	s.inflight.Add(1)
	go func() {
		defer s.inflight.Done()
		s.runValidateJob(jobID, cfg)
	}()

	writeJSON(w, http.StatusAccepted, validateStartResponse{
		JobID:     jobID,
		StatusURL: "/api/validate/status?job_id=" + jobID,
	})
}

func (s *Server) handleValidateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := requireReadAuthorizationForAction(w, r, "validate_status"); !ok {
		return
	}

	jobID := strings.TrimSpace(r.URL.Query().Get("job_id"))
	if jobID == "" {
		writeError(w, http.StatusBadRequest, "job_id is required")
		return
	}

	status, ok := s.getValidateJob(jobID)
	if !ok {
		writeError(w, http.StatusNotFound, "validate job not found")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) buildValidateRunnerConfig(r *http.Request) (runner.Config, int, error) {
	if err := r.ParseMultipartForm(maxMultipartFormBytes); err != nil {
		return runner.Config{}, http.StatusBadRequest, fmt.Errorf("parse multipart form: %w", err)
	}

	requestDir, err := s.newUploadDir()
	if err != nil {
		return runner.Config{}, http.StatusInternalServerError, err
	}

	artifactPath, err := extractArtifact(r, requestDir)
	if err != nil {
		return runner.Config{}, http.StatusBadRequest, err
	}
	manifestPath, err := extractManifest(r, requestDir)
	if err != nil {
		return runner.Config{}, http.StatusBadRequest, err
	}
	matrixPath, err := s.resolveMatrixPath(r, requestDir)
	if err != nil {
		return runner.Config{}, http.StatusBadRequest, err
	}

	timeoutText := strings.TrimSpace(r.FormValue("timeout"))
	timeout := s.cfg.DefaultTimeout
	if timeoutText != "" {
		timeout, err = time.ParseDuration(timeoutText)
		if err != nil {
			return runner.Config{}, http.StatusBadRequest, fmt.Errorf("invalid timeout: %w", err)
		}
	}
	if timeout <= 0 {
		return runner.Config{}, http.StatusBadRequest, fmt.Errorf("timeout must be greater than zero")
	}
	maxTimeout := maxValidateTimeout()
	if timeout > maxTimeout {
		return runner.Config{}, http.StatusBadRequest, fmt.Errorf("timeout exceeds max allowed (%s)", maxTimeout)
	}
	concurrency := parseIntOrDefault(r.FormValue("concurrency"), s.cfg.DefaultConcurrency)
	if concurrency < 1 {
		concurrency = 1
	}
	maxConcurrency := maxValidateConcurrency()
	if concurrency > maxConcurrency {
		return runner.Config{}, http.StatusBadRequest, fmt.Errorf("concurrency exceeds max allowed (%d)", maxConcurrency)
	}

	reportBase := "ui-" + shortID()
	reportJSONPath := filepath.Join("reports", reportBase+".json")
	reportMarkdownPath := filepath.Join("reports", reportBase+".md")

	cfg := runner.Config{
		ArtifactPath:    artifactPath,
		ArtifactURI:     strings.TrimSpace(r.FormValue("artifact_uri")),
		ArtifactName:    strings.TrimSpace(r.FormValue("artifact_name")),
		ArtifactVersion: strings.TrimSpace(r.FormValue("artifact_version")),
		ArtifactVariant: strings.TrimSpace(r.FormValue("artifact_variant")),
		ValidationMode:  strings.TrimSpace(r.FormValue("validation_mode")),
		MatrixPath:      matrixPath,
		ManifestPath:    manifestPath,
		OutPath:         reportJSONPath,
		MarkdownPath:    reportMarkdownPath,
		WorkDir:         s.cfg.WorkDir,
		Runner:          runner.RunnerVM,
		Concurrency:     concurrency,
		Timeout:         timeout,
	}
	if err := cfg.Validate(); err != nil {
		return runner.Config{}, http.StatusBadRequest, fmt.Errorf("invalid request config: %w", err)
	}
	return cfg, 0, nil
}

func (s *Server) runValidateJob(jobID string, cfg runner.Config) {
	if !s.waitForValidateRunSlot(jobID) {
		return
	}

	result, err := s.validateRunner()(context.Background(), cfg)
	if err != nil {
		s.updateValidateJob(jobID, func(job *validateJob) {
			job.State = "failed"
			job.Stage = "failed"
			job.Message = "Validation failed"
			job.Error = err.Error()
			job.FinishedAt = time.Now().UTC()
		})
		recordValidateJobTerminal("failed")
		s.refreshValidateJobsGauge()
		return
	}
	if err := s.autoSyncValidationArtifact(cfg, result); err != nil {
		s.log().Warn("auto-sync registry warning", slog.String("error", err.Error()))
	}

	response := &validateResponse{
		ExitCode:           result.ExitCode,
		RunDir:             result.RunDir,
		ReportJSONPath:     result.Report.Paths.JSON,
		ReportMarkdownPath: result.Report.Paths.Markdown,
		Report:             result.Report,
	}
	s.updateValidateJob(jobID, func(job *validateJob) {
		job.State = "completed"
		job.Stage = string(runner.ProgressStageCompleted)
		job.Message = "Validation completed"
		job.Percent = 100
		job.Response = response
		job.Error = ""
		job.FinishedAt = time.Now().UTC()
	})
	recordValidateJobTerminal("completed")
	s.refreshValidateJobsGauge()
}

// refreshValidateJobsGauge snapshots the in-memory job store under the same
// lock that owns it, then publishes counts to the Prometheus gauges. Called
// after any state transition so the gauge tracks reality.
func (s *Server) refreshValidateJobsGauge() {
	s.validateJobs.mu.RLock()
	active, queued := s.validateJobCountsLocked()
	s.validateJobs.mu.RUnlock()
	recordValidateJobsGauge(active, queued)
}

func (s *Server) applyRunnerProgress(jobID string, update runner.ProgressUpdate) {
	stage := strings.TrimSpace(string(update.Stage))
	if stage == "" {
		stage = "running"
	}
	s.updateValidateJob(jobID, func(job *validateJob) {
		job.State = "running"
		job.Stage = stage
		if msg := strings.TrimSpace(update.Message); msg != "" {
			job.Message = msg
		}
		if update.TotalProfiles > 0 {
			job.TotalProfiles = update.TotalProfiles
		}
		if update.CompletedProfiles >= 0 {
			job.CompletedProfiles = update.CompletedProfiles
		}
		if profileID := strings.TrimSpace(update.ProfileID); profileID != "" {
			if job.ProfileStatusByID == nil {
				job.ProfileStatusByID = make(map[string]string)
			}
			status := strings.TrimSpace(update.ProfileStatus)
			if status == "" {
				status = "running"
			}
			job.ProfileStatusByID[profileID] = status
		}
		nextPercent := estimateValidateProgressPercent(stage, job.CompletedProfiles, job.TotalProfiles)
		if nextPercent > job.Percent {
			job.Percent = nextPercent
		}
	})
}

func estimateValidateProgressPercent(stage string, completedProfiles, totalProfiles int) int {
	switch stage {
	case string(runner.ProgressStagePrepareRun):
		return 5
	case string(runner.ProgressStageInspectArtifact):
		return 15
	case string(runner.ProgressStageStageArtifact):
		return 25
	case string(runner.ProgressStageLoadMatrix):
		return 35
	case string(runner.ProgressStageLoadManifest):
		return 40
	case string(runner.ProgressStageValidateTargets):
		if totalProfiles <= 0 {
			return 50
		}
		if completedProfiles < 0 {
			completedProfiles = 0
		}
		if completedProfiles > totalProfiles {
			completedProfiles = totalProfiles
		}
		return 45 + (completedProfiles*45)/totalProfiles
	case string(runner.ProgressStageWriteReport):
		return 92
	case string(runner.ProgressStagePersistRegistry):
		return 97
	case string(runner.ProgressStageCompleted):
		return 100
	default:
		return 5
	}
}

func (s *Server) ensureValidateJobCapacity() error {
	s.validateJobs.mu.RLock()
	defer s.validateJobs.mu.RUnlock()

	active, queued := s.validateJobCountsLocked()
	maxActive := maxActiveValidateJobs()
	maxQueued := maxQueuedValidateJobs()
	if active < maxActive {
		return nil
	}
	if queued >= maxQueued {
		return fmt.Errorf(
			"validate queue is full (active=%d/%d queued=%d/%d); try again later",
			active,
			maxActive,
			queued,
			maxQueued,
		)
	}
	return nil
}

func (s *Server) waitForValidateRunSlot(jobID string) bool {
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	for {
		acquired := false
		s.validateJobs.mu.Lock()
		if s.validateJobs.jobs == nil {
			s.validateJobs.jobs = make(map[string]*validateJob)
		}
		job, ok := s.validateJobs.jobs[jobID]
		if !ok {
			s.validateJobs.mu.Unlock()
			return false
		}

		active, _ := s.validateJobCountsLocked()
		if job.State == "running" {
			acquired = true
		} else if active < maxActiveValidateJobs() {
			job.State = "running"
			job.Stage = "queued"
			job.Message = "Validation job started"
			if job.Percent < 1 {
				job.Percent = 1
			}
			if job.StartedAt.IsZero() {
				job.StartedAt = time.Now().UTC()
			}
			job.UpdatedAt = time.Now().UTC()
			acquired = true
		}
		s.validateJobs.mu.Unlock()

		if acquired {
			return true
		}
		<-ticker.C
	}
}

func (s *Server) validateJobCountsLocked() (active int, queued int) {
	for _, job := range s.validateJobs.jobs {
		switch job.State {
		case "running":
			active++
		case "queued":
			queued++
		}
	}
	return active, queued
}

func (s *Server) createValidateJob(profileIDs []string) string {
	s.validateJobs.mu.Lock()
	defer s.validateJobs.mu.Unlock()
	if s.validateJobs.jobs == nil {
		s.validateJobs.jobs = make(map[string]*validateJob)
	}

	now := time.Now().UTC()
	jobID := "val-" + shortID()
	profileStatuses := make(map[string]string, len(profileIDs))
	for _, profileID := range profileIDs {
		cleanID := strings.TrimSpace(profileID)
		if cleanID == "" {
			continue
		}
		profileStatuses[cleanID] = "pending"
	}
	s.validateJobs.jobs[jobID] = &validateJob{
		JobID:             jobID,
		State:             "queued",
		Stage:             "queued",
		Message:           "Validation job queued",
		Percent:           0,
		TotalProfiles:     len(profileStatuses),
		CompletedProfiles: 0,
		ProfileStatusByID: profileStatuses,
		StartedAt:         now,
		UpdatedAt:         now,
	}

	s.trimValidateJobsLocked()
	return jobID
}

func (s *Server) updateValidateJob(jobID string, mutate func(job *validateJob)) {
	s.validateJobs.mu.Lock()
	defer s.validateJobs.mu.Unlock()
	if s.validateJobs.jobs == nil {
		s.validateJobs.jobs = make(map[string]*validateJob)
	}
	job, ok := s.validateJobs.jobs[jobID]
	if !ok {
		return
	}
	mutate(job)
	job.Percent = clamp(job.Percent, 0, 100)
	if job.StartedAt.IsZero() {
		job.StartedAt = time.Now().UTC()
	}
	job.UpdatedAt = time.Now().UTC()
}

func (s *Server) getValidateJob(jobID string) (validateStatusResponse, bool) {
	s.validateJobs.mu.RLock()
	defer s.validateJobs.mu.RUnlock()
	if s.validateJobs.jobs == nil {
		return validateStatusResponse{}, false
	}
	job, ok := s.validateJobs.jobs[jobID]
	if !ok {
		return validateStatusResponse{}, false
	}

	profileStatuses := make(map[string]string, len(job.ProfileStatusByID))
	for id, status := range job.ProfileStatusByID {
		profileStatuses[id] = status
	}

	resp := validateStatusResponse{
		JobID:             job.JobID,
		State:             job.State,
		Stage:             job.Stage,
		Message:           job.Message,
		Percent:           clamp(job.Percent, 0, 100),
		TotalProfiles:     job.TotalProfiles,
		CompletedProfiles: job.CompletedProfiles,
		ProfileStatuses:   profileStatuses,
		Result:            job.Response,
		Error:             job.Error,
	}
	if !job.StartedAt.IsZero() {
		resp.StartedAt = job.StartedAt.UTC().Format(time.RFC3339)
	}
	if !job.UpdatedAt.IsZero() {
		resp.UpdatedAt = job.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if !job.FinishedAt.IsZero() {
		resp.FinishedAt = job.FinishedAt.UTC().Format(time.RFC3339)
	}
	return resp, true
}

func (s *Server) trimValidateJobsLocked() {
	if len(s.validateJobs.jobs) <= maxStoredValidateJobs {
		return
	}

	finished := make([]*validateJob, 0, len(s.validateJobs.jobs))
	for _, job := range s.validateJobs.jobs {
		if job.State == "completed" || job.State == "failed" {
			finished = append(finished, job)
		}
	}
	sort.Slice(finished, func(i, j int) bool {
		return finished[i].UpdatedAt.Before(finished[j].UpdatedAt)
	})

	for len(s.validateJobs.jobs) > maxStoredValidateJobs && len(finished) > 0 {
		oldest := finished[0]
		finished = finished[1:]
		delete(s.validateJobs.jobs, oldest.JobID)
	}
}

func (s *Server) newUploadDir() (string, error) {
	dir := filepath.Join(filepath.Clean(s.cfg.WorkDir), "uploads", shortID())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create upload directory: %w", err)
	}
	return dir, nil
}

func (s *Server) resolveMatrixPath(r *http.Request, requestDir string) (string, error) {
	selectedProfiles := collectMultiValues(r.MultipartForm.Value["profiles"])
	requiredProfiles := collectMultiValues(r.MultipartForm.Value["required_profiles"])

	if len(selectedProfiles) == 0 {
		if strings.TrimSpace(s.cfg.DefaultMatrixPath) == "" {
			return "", fmt.Errorf("no profiles selected and default matrix path is empty")
		}
		return s.cfg.DefaultMatrixPath, nil
	}
	if len(selectedProfiles) > maxValidateProfiles() {
		return "", fmt.Errorf("selected profiles exceed max allowed (%d)", maxValidateProfiles())
	}

	catalog, err := s.profileCatalogSet()
	if err != nil {
		return "", err
	}

	selectedSet := make(map[string]struct{}, len(selectedProfiles))
	for _, id := range selectedProfiles {
		if !apiProfileIDPattern.MatchString(id) {
			return "", fmt.Errorf("invalid profile id %q", id)
		}
		if _, ok := catalog[id]; !ok {
			return "", fmt.Errorf("unknown profile id %q", id)
		}
		selectedSet[id] = struct{}{}
	}
	for _, id := range requiredProfiles {
		if !apiProfileIDPattern.MatchString(id) {
			return "", fmt.Errorf("invalid required profile id %q", id)
		}
		if _, ok := selectedSet[id]; !ok {
			return "", fmt.Errorf("required profile %q must also be selected", id)
		}
	}

	requiredSet := make(map[string]struct{}, len(requiredProfiles))
	for _, id := range requiredProfiles {
		requiredSet[id] = struct{}{}
	}

	type profileRow struct {
		ID       string `yaml:"id"`
		Required bool   `yaml:"required"`
	}
	matrixDoc := struct {
		Name     string       `yaml:"name"`
		Profiles []profileRow `yaml:"profiles"`
	}{
		Name: "ui-selection",
	}
	for _, id := range selectedProfiles {
		_, required := requiredSet[id]
		matrixDoc.Profiles = append(matrixDoc.Profiles, profileRow{ID: id, Required: required})
	}

	payload, err := yaml.Marshal(matrixDoc)
	if err != nil {
		return "", fmt.Errorf("marshal matrix yaml: %w", err)
	}
	matrixPath := filepath.Join(requestDir, "matrix.yaml")
	if err := os.WriteFile(matrixPath, payload, 0o644); err != nil {
		return "", fmt.Errorf("write matrix yaml: %w", err)
	}
	return matrixPath, nil
}

func (s *Server) profileCatalogSet() (map[string]struct{}, error) {
	profiles, err := s.listProfiles()
	if err != nil {
		return nil, fmt.Errorf("load profile catalog: %w", err)
	}
	catalog := make(map[string]struct{}, len(profiles))
	for _, p := range profiles {
		id := strings.TrimSpace(p.ID)
		if id == "" {
			continue
		}
		catalog[id] = struct{}{}
	}
	if len(catalog) == 0 {
		return nil, fmt.Errorf("profile catalog is empty")
	}
	return catalog, nil
}

func (s *Server) listProfiles() ([]profileInfo, error) {
	requiredMap := make(map[string]bool)
	if strings.TrimSpace(s.cfg.DefaultMatrixPath) != "" {
		m, err := matrix.Load(s.cfg.DefaultMatrixPath)
		if err != nil {
			return nil, fmt.Errorf("load default matrix: %w", err)
		}
		for _, p := range m.Profiles {
			requiredMap[p.ID] = p.RequiredBool()
		}
	}

	paths, err := discoverVMProfilePaths()
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	profiles := make([]profileInfo, 0, len(paths))
	for _, p := range paths {
		profile, err := vm.LoadProfile(p)
		if err != nil {
			return nil, fmt.Errorf("load profile %q: %w", p, err)
		}
		if !apiProfileIDPattern.MatchString(strings.TrimSpace(profile.ID)) {
			return nil, fmt.Errorf("profile %q has invalid id %q", p, profile.ID)
		}
		imagePath := strings.TrimSpace(profile.Image.LocalPath)
		sourceURL := strings.TrimSpace(profile.Image.SourceURL)
		sourceMode := "manual-local"
		if sourceURL != "" {
			sourceMode = "url"
		}
		imageCached := false
		if imagePath != "" {
			if _, err := os.Stat(imagePath); err == nil {
				imageCached = true
			}
		}
		transport, transportSupported, transportReason := vm.ExecutionTransport(profile)
		profiles = append(profiles, profileInfo{
			ID:                 profile.ID,
			Distro:             profile.Distro,
			Version:            profile.Version,
			KernelFamily:       profile.KernelFamily,
			Arch:               profile.Arch,
			RequiredDefault:    requiredMap[profile.ID],
			ImageLocalPath:     imagePath,
			ImageCached:        imageCached,
			SourceMode:         sourceMode,
			SourceURL:          sourceURL,
			Transport:          transport,
			TransportSupported: transportSupported,
			TransportNote:      transportReason,
		})
	}
	return profiles, nil
}

func discoverVMProfilePaths() ([]string, error) {
	patterns := []string{
		filepath.Join("vm", "profiles", "*.yaml"),
		filepath.Join("..", "..", "vm", "profiles", "*.yaml"),
	}
	for _, pattern := range patterns {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("discover vm profile files (%s): %w", pattern, err)
		}
		if len(paths) > 0 {
			return paths, nil
		}
	}
	return nil, fmt.Errorf("discover vm profile files: none found in known paths")
}

func extractArtifact(r *http.Request, requestDir string) (string, error) {
	if file, header, err := r.FormFile("artifact_file"); err == nil {
		defer file.Close()
		path := filepath.Join(requestDir, sanitizeFileName(header.Filename, "uploaded-artifact.bpf.o"))
		if err := writeUploadedFile(path, file); err != nil {
			return "", err
		}
		return path, nil
	}

	sourceText := r.FormValue("source_code")
	if sourceFile, header, err := r.FormFile("source_file"); err == nil {
		defer sourceFile.Close()
		sourcePath := filepath.Join(requestDir, sanitizeFileName(header.Filename, "uploaded-source.bpf.c"))
		if err := writeUploadedFile(sourcePath, sourceFile); err != nil {
			return "", err
		}
		return compileSourceFile(sourcePath, requestDir, strings.TrimSpace(r.FormValue("clang_flags")))
	}

	if strings.TrimSpace(sourceText) != "" {
		sourcePath := filepath.Join(requestDir, "uploaded-source.bpf.c")
		if err := os.WriteFile(sourcePath, []byte(sourceText), 0o644); err != nil {
			return "", fmt.Errorf("write source text: %w", err)
		}
		return compileSourceFile(sourcePath, requestDir, strings.TrimSpace(r.FormValue("clang_flags")))
	}

	return "", fmt.Errorf("provide artifact_file, source_file, or source_code")
}

func extractManifest(r *http.Request, requestDir string) (string, error) {
	if file, header, err := r.FormFile("manifest_file"); err == nil {
		defer file.Close()
		path := filepath.Join(requestDir, sanitizeFileName(header.Filename, "manifest.yaml"))
		if err := writeUploadedFile(path, file); err != nil {
			return "", err
		}
		return path, nil
	}

	manifestText := strings.TrimSpace(r.FormValue("manifest_text"))
	if manifestText == "" {
		return "", nil
	}
	path := filepath.Join(requestDir, "manifest.yaml")
	if err := os.WriteFile(path, []byte(manifestText), 0o644); err != nil {
		return "", fmt.Errorf("write manifest text: %w", err)
	}
	return path, nil
}

func writeUploadedFile(path string, src multipart.File) error {
	dst, err := os.Create(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("create upload file: %w", err)
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("write upload file: %w", err)
	}
	return nil
}

func compileSourceFile(sourcePath, requestDir, extraFlags string) (string, error) {
	outPath := filepath.Join(requestDir, "compiled.bpf.o")
	allowedExtraFlags, err := sanitizeExtraClangFlags(extraFlags)
	if err != nil {
		return "", err
	}

	args := []string{
		"-O2",
		"-g",
		"-target", "bpf",
		"-D__TARGET_ARCH_x86",
		"-I/usr/include/x86_64-linux-gnu",
		"-c", sourcePath,
		"-o", outPath,
	}
	if len(allowedExtraFlags) > 0 {
		args = append(allowedExtraFlags, args...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), sourceCompileTimeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, "clang", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("clang compile timed out after %s", sourceCompileTimeout())
		}
		trimmed := strings.TrimSpace(string(output))
		hint := compileFailureHint(trimmed)
		if hint != "" {
			return "", fmt.Errorf("clang compile failed: %v\n%s\nhint: %s", err, trimmed, hint)
		}
		return "", fmt.Errorf("clang compile failed: %v\n%s", err, trimmed)
	}
	return outPath, nil
}

func sanitizeExtraClangFlags(extraFlags string) ([]string, error) {
	flags := splitShellWords(extraFlags)
	if len(flags) == 0 {
		return nil, nil
	}
	if !sourceCompileAllowExtraFlags() {
		return nil, fmt.Errorf("clang_flags are disabled by server policy")
	}
	safe := make([]string, 0, len(flags))
	for _, flag := range flags {
		if !apiAllowedClangFlagPattern.MatchString(flag) {
			return nil, fmt.Errorf("unsupported clang flag %q; only -D/-U preprocessor flags are allowed", flag)
		}
		safe = append(safe, flag)
	}
	return safe, nil
}

func compileFailureHint(output string) string {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "incomplete definition of type") ||
		strings.Contains(lower, "unknown type name"):
		return "the uploaded source references kernel types without required headers; provide vmlinux.h/include headers or upload a prebuilt .bpf.o artifact"
	case strings.Contains(lower, "fatal error:") && strings.Contains(lower, "file not found"):
		return "a required header is missing; bundle headers with the source flow or upload a prebuilt .bpf.o artifact"
	default:
		return ""
	}
}

func sanitizeFileName(value, fallback string) string {
	// SECURITY: the result is interpolated into downstream shell commands
	// (qemu/SSH validator invocation). filepath.Base alone leaves shell
	// metacharacters intact, which lets a crafted filename inject arbitrary
	// commands in the guest VM. Require a strict allowlist instead and fall
	// back to a safe default if the upload uses any other character.
	cleaned := strings.TrimSpace(filepath.Base(value))
	if cleaned == "" || cleaned == "." || cleaned == "/" {
		return fallback
	}
	if !apiSafeUploadFileNamePattern.MatchString(cleaned) {
		return fallback
	}
	return cleaned
}

func splitShellWords(input string) []string {
	raw := strings.Fields(input)
	out := make([]string, 0, len(raw))
	for _, token := range raw {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		out = append(out, token)
	}
	return out
}

func collectMultiValues(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		parts := strings.Split(value, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, ok := seen[part]; ok {
				continue
			}
			seen[part] = struct{}{}
			out = append(out, part)
		}
	}
	sort.Strings(out)
	return out
}

func parseIntOrDefault(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func parseRuntimeProbeOptionsQuery(r *http.Request) (runtime.ProbeOptions, error) {
	query := r.URL.Query()
	preferPrivileged, err := parseBoolQueryValue(query.Get("prefer_privileged"), false)
	if err != nil {
		return runtime.ProbeOptions{}, fmt.Errorf("invalid prefer_privileged: %w", err)
	}
	useSudo, err := parseBoolQueryValue(query.Get("use_sudo"), true)
	if err != nil {
		return runtime.ProbeOptions{}, fmt.Errorf("invalid use_sudo: %w", err)
	}
	sudoNonInteractive, err := parseBoolQueryValue(query.Get("sudo_non_interactive"), true)
	if err != nil {
		return runtime.ProbeOptions{}, fmt.Errorf("invalid sudo_non_interactive: %w", err)
	}
	return runtime.ProbeOptions{
		PreferPrivileged:   preferPrivileged,
		UseSudo:            useSudo,
		SudoNonInteractive: sudoNonInteractive,
	}, nil
}

func parseBoolQueryValue(value string, fallback bool) (bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback, err
	}
	return parsed, nil
}

func (s *Server) autoSyncValidationArtifact(cfg runner.Config, result runner.RunResult) error {
	if !autoSyncRegistryEnabled() {
		return nil
	}
	tenant := strings.TrimSpace(os.Getenv(envAutoSyncTenant))
	project := strings.TrimSpace(os.Getenv(envAutoSyncProject))
	if tenant == "" || project == "" {
		return fmt.Errorf(
			"%s=true requires %s and %s",
			envAutoSyncRegistry,
			envAutoSyncTenant,
			envAutoSyncProject,
		)
	}
	visibility := strings.ToLower(strings.TrimSpace(os.Getenv(envAutoSyncProjectVisibility)))
	if visibility == "" {
		visibility = "private"
	}

	artifactName := strings.TrimSpace(cfg.ArtifactName)
	if artifactName == "" {
		artifactName = strings.TrimSpace(result.Report.Artifact.BaseName)
	}
	artifactVersion := strings.TrimSpace(cfg.ArtifactVersion)
	if artifactVersion == "" {
		artifactVersion = strings.TrimSpace(result.Report.Run.ID)
	}
	if artifactName == "" || artifactVersion == "" {
		return fmt.Errorf("auto-sync could not resolve artifact name/version")
	}

	store := cloudregistry.NewStore(s.cfg.WorkDir)
	if _, err := store.UpsertProject(cloudregistry.CreateProjectInput{
		Tenant:     tenant,
		Project:    project,
		Visibility: visibility,
	}); err != nil {
		return fmt.Errorf("auto-sync upsert project: %w", err)
	}

	if _, err := store.ResolveArtifactVersion(tenant, project, artifactName, artifactVersion); err == nil {
		return nil
	} else if !errors.Is(err, cloudregistry.ErrNotFound) {
		return fmt.Errorf("auto-sync resolve existing record: %w", err)
	}

	artifactPath := strings.TrimSpace(result.Report.Artifact.Path)
	if artifactPath == "" {
		artifactPath = strings.TrimSpace(cfg.ArtifactPath)
	}
	if artifactPath == "" {
		return fmt.Errorf("auto-sync missing artifact path")
	}
	f, err := os.Open(filepath.Clean(artifactPath))
	if err != nil {
		return fmt.Errorf("auto-sync open artifact: %w", err)
	}
	defer f.Close()

	reportCopy := result.Report
	_, err = store.UploadArtifact(cloudregistry.UploadInput{
		Tenant:          tenant,
		Project:         project,
		ArtifactName:    artifactName,
		ArtifactVersion: artifactVersion,
		ArtifactVariant: strings.TrimSpace(cfg.ArtifactVariant),
		ArtifactURI:     strings.TrimSpace(cfg.ArtifactURI),
		ManifestPath:    strings.TrimSpace(cfg.ManifestPath),
		ExpectedSHA256:  strings.TrimSpace(result.Report.Artifact.SHA256),
		SourceRunID:     strings.TrimSpace(result.Report.Run.ID),
		ArtifactReader:  f,
		Report:          &reportCopy,
	})
	if err != nil {
		if errors.Is(err, cloudregistry.ErrConflict) {
			return nil
		}
		return fmt.Errorf("auto-sync upload artifact: %w", err)
	}
	return nil
}

func extractRegistryReport(r *http.Request) (*schema.ReportV01, error) {
	if file, _, err := r.FormFile("report_file"); err == nil {
		defer file.Close()
		raw, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("read report_file: %w", err)
		}
		return decodeRegistryReportPayload(raw)
	}
	reportText := strings.TrimSpace(r.FormValue("report_json"))
	if reportText == "" {
		return nil, nil
	}
	return decodeRegistryReportPayload([]byte(reportText))
}

func decodeRegistryReportPayload(raw []byte) (*schema.ReportV01, error) {
	var report schema.ReportV01
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse report JSON: %w", err)
	}
	return &report, nil
}

func bearerToken(r *http.Request) string {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return strings.TrimSpace(r.Header.Get("X-API-Token"))
	}
	const prefix = "Bearer "
	if strings.HasPrefix(authHeader, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
	}
	return strings.TrimSpace(authHeader)
}

func tokenSubject(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return "anonymous"
	}
	digest := sha256.Sum256([]byte(token))
	return "token:" + hex.EncodeToString(digest[:6])
}

func actorFromPrincipal(principal cloudregistry.Principal, token string) string {
	subject := strings.TrimSpace(principal.Subject)
	if subject != "" {
		return subject
	}
	return tokenSubject(token)
}

func appendRegistryAuditBestEffort(store cloudregistry.Store, event cloudregistry.AuditEvent) {
	_, _ = store.AppendAudit(event)
}

func authzStatus(err error) int {
	switch {
	case errors.Is(err, cloudregistry.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, cloudregistry.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, errRegistryRateLimited):
		return http.StatusTooManyRequests
	default:
		return http.StatusBadRequest
	}
}

func shortID() string {
	// SECURITY: a timestamp-derived ID is enumerable, which lets unauthenticated
	// callers harvest other tenants' validate jobs / correlation traces. Use 16
	// bytes of crypto/rand; fall back to the timestamp only if the entropy
	// source fails (extremely unlikely on a healthy host).
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return hex.EncodeToString(buf)
}

func listenAddressForHumans(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}

func registryProjectWorkDir(workDir, tenant, project string) string {
	return filepath.Join(
		filepath.Clean(strings.TrimSpace(workDir)),
		"cloud-registry",
		"tenants",
		tenant,
		"projects",
		project,
	)
}

func runRuntimeExecuteWorker(ctx context.Context, req runtime.ExecuteRequest) (runtime.ExecuteResult, error) {
	workerBinary := strings.TrimSpace(os.Getenv(envRuntimeExecWorker))
	if workerBinary == "" {
		self, err := os.Executable()
		if err != nil {
			return runtime.ExecuteResult{}, fmt.Errorf("resolve runtime worker binary: %w", err)
		}
		workerBinary = self
	}
	workerUser := runtimeExecuteWorkerUser()

	payload, err := json.Marshal(runtime.ExecuteWorkerRequest{Execute: req})
	if err != nil {
		return runtime.ExecuteResult{}, fmt.Errorf("encode runtime worker request: %w", err)
	}

	name, args := runtimeExecuteWorkerCommand(workerBinary, workerUser)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(payload)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText == "" {
			stderrText = strings.TrimSpace(stdout.String())
		}
		if stderrText == "" {
			stderrText = err.Error()
		}
		return runtime.ExecuteResult{}, fmt.Errorf("runtime worker process failed: %s", stderrText)
	}

	var resp runtime.ExecuteWorkerResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return runtime.ExecuteResult{}, fmt.Errorf("decode runtime worker response: %w", err)
	}
	return resp.Execution, nil
}

func runtimeExecuteWorkerCommand(workerBinary, workerUser string) (string, []string) {
	cleanBinary := filepath.Clean(strings.TrimSpace(workerBinary))
	if cleanBinary == "" {
		cleanBinary = "bpfcompat"
	}
	workerUser = strings.TrimSpace(workerUser)
	if workerUser == "" {
		return cleanBinary, []string{"runtime", "worker-execute"}
	}
	// SECURITY: "--" stops sudo flag parsing between sudo's own options and
	// the command to execute. Without it, an env-supplied workerBinary that
	// starts with "-" could be reinterpreted by sudo as another flag.
	return "sudo", []string{"-n", "-u", workerUser, "--", cleanBinary, "runtime", "worker-execute"}
}

func runtimeExecuteWorkerUser() string {
	return strings.TrimSpace(os.Getenv(envRuntimeExecWorkerUser))
}

func runtimeExecuteRequireWorkerIdentity() bool {
	return parseBoolEnv(envRuntimeExecRequireWorkerIdentity, false)
}

func runtimeExecuteWorkerIdentityLabel(workerUser string) string {
	workerUser = strings.TrimSpace(workerUser)
	if workerUser == "" {
		return "process-default"
	}
	return "os-user:" + workerUser
}

func writeCredentialFromRequest(r *http.Request) string {
	provided := strings.TrimSpace(r.Header.Get(headerAPIKey))
	if provided == "" {
		provided = bearerToken(r)
	}
	return provided
}

func requireRuntimeExecuteApproval(w http.ResponseWriter, r *http.Request, writeIdentity writeAuthIdentity) (approvedBy string, requestedBy string, ok bool) {
	expected := strings.TrimSpace(os.Getenv(envRuntimeExecApprove))
	if expected == "" {
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("runtime execute approval token is not configured; set %s", envRuntimeExecApprove))
		return "", "", false
	}

	provided := strings.TrimSpace(r.Header.Get(headerExecApprove))
	if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
		writeError(w, http.StatusForbidden, "missing or invalid runtime execute approval token")
		return "", "", false
	}

	approvedBy = strings.TrimSpace(r.Header.Get(headerExecApprovedBy))
	if approvedBy == "" {
		approvedBy = "unspecified"
	}
	requestedBy = writeIdentitySubject(writeIdentity, r)
	return approvedBy, requestedBy, true
}

func runtimeExecuteEnabled() bool {
	return parseBoolEnv(envAllowRuntimeExec, false)
}

func runtimeExecuteKillSwitchEnabled() bool {
	return parseBoolEnv(envRuntimeExecKill, false)
}

func autoSyncRegistryEnabled() bool {
	return parseBoolEnv(envAutoSyncRegistry, false)
}

func redactRuntimeDetailsEnabled() bool {
	return parseBoolEnv(envRedactRuntime, true)
}

func parseBoolEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func maxActiveValidateJobs() int {
	return parseBoundedIntEnv(envMaxActiveValidateJobs, defaultMaxActiveValidateJobs, 1, 64)
}

func maxQueuedValidateJobs() int {
	return parseBoundedIntEnv(envMaxQueuedValidateJobs, defaultMaxQueuedValidateJobs, 0, 256)
}

func maxValidateConcurrency() int {
	return parseBoundedIntEnv(envMaxValidateConcurrency, defaultMaxValidateConcurrency, 1, 64)
}

func maxValidateProfiles() int {
	return parseBoundedIntEnv(envMaxValidateProfiles, defaultMaxValidateProfiles, 1, 256)
}

func maxValidateTimeout() time.Duration {
	return parseBoundedDurationEnv(envMaxValidateTimeout, defaultMaxValidateTimeout, time.Minute, 2*time.Hour)
}

func sourceCompileTimeout() time.Duration {
	return parseBoundedDurationEnv(envSourceCompileTimeout, defaultSourceCompileTimeout, 5*time.Second, 5*time.Minute)
}

func sourceCompileAllowExtraFlags() bool {
	return parseBoolEnv(envSourceCompileAllowExtraFlags, false)
}

func parseBoundedIntEnv(key string, fallback, minValue, maxValue int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	if parsed < minValue {
		return minValue
	}
	if parsed > maxValue {
		return maxValue
	}
	return parsed
}

func parseBoundedDurationEnv(key string, fallback, minValue, maxValue time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	if parsed < minValue {
		return minValue
	}
	if parsed > maxValue {
		return maxValue
	}
	return parsed
}

func withSecurityHeaders(next http.Handler, tlsEnabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		// Only advertise HSTS when we are actually serving HTTPS — otherwise
		// the header is meaningless and misleads clients about the transport.
		if tlsEnabled {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		// Default CSP for non-HTML responses (JSON APIs). HTML routes
		// override this with nonce-scoped policies for their style/script
		// blocks without re-introducing 'unsafe-inline'.
		// "default-src 'none'" is the most restrictive baseline; anything
		// the JSON endpoints actually need is allowed explicitly.
		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
		)
		next.ServeHTTP(w, r)
	})
}

func sanitizeHostProbeForAPI(probe runtime.HostCapabilities) runtime.HostCapabilities {
	out := probe
	out.Host.Hostname = "demo-host"
	return out
}

func sanitizeFetchResultForAPI(fetch runtime.FetchResult) runtime.FetchResult {
	out := fetch
	out.SourcePath = redactPathValue(out.SourcePath)
	out.OutputPath = redactPathValue(out.OutputPath)
	return out
}

func sanitizeExecuteResultForAPI(execResult runtime.ExecuteResult) runtime.ExecuteResult {
	out := execResult
	out.ArtifactPath = redactPathValue(out.ArtifactPath)
	out.ManifestPath = redactPathValue(out.ManifestPath)
	out.RunDir = redactPathValue(out.RunDir)
	out.LogDir = redactPathValue(out.LogDir)
	out.ValidatorResultPath = redactPathValue(out.ValidatorResultPath)
	out.StderrPath = redactPathValue(out.StderrPath)
	out.Stderr = ""
	for i := range out.Command {
		if strings.Contains(out.Command[i], "/") || strings.Contains(out.Command[i], "\\") {
			out.Command[i] = redactPathValue(out.Command[i])
		}
	}
	return out
}

func redactPathValue(pathValue string) string {
	value := strings.TrimSpace(pathValue)
	if value == "" {
		return ""
	}
	base := filepath.Base(filepath.Clean(value))
	if base == "" || base == "." || base == "/" {
		return "[redacted]"
	}
	return "[redacted]/" + base
}

// decodeJSONBody caps the request body at maxJSONRequestBytes via
// http.MaxBytesReader, then JSON-decodes into dst. It also rejects bodies
// that contain trailing junk after the JSON value (common smuggling shape).
// Callers receive a single error suitable for writeError; HTTP-413 mapping is
// handled by the caller-supplied status mapping (writeError uses 400 by
// default, which is fine for nearly all malformed-body cases).
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.Body == nil {
		return fmt.Errorf("request body is required")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONRequestBytes)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		// http.MaxBytesReader surfaces a *http.MaxBytesError on overflow.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return fmt.Errorf("request body exceeds %d bytes", maxJSONRequestBytes)
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	// Reject extra content after the first JSON value so callers can't smuggle
	// a second document past validation.
	if dec.More() {
		return fmt.Errorf("request body must contain exactly one JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error": redactErrorMessage(message),
	})
}

// redactErrorMessage strips absolute filesystem paths from error strings
// emitted to API clients when path-detail redaction is enabled. The runtime
// success path already runs through sanitizeFetchResultForAPI /
// sanitizeExecuteResultForAPI; before this change the *failure* path leaked
// raw err.Error() values that routinely contained server-internal paths
// (workdir, registry storage, validator binary, manifest paths). The
// redacted form keeps the basename so the operator can still match the file
// against logs without exposing the full directory layout.
func redactErrorMessage(message string) string {
	if !redactRuntimeDetailsEnabled() {
		return message
	}
	if message == "" {
		return message
	}
	return apiAbsolutePathPattern.ReplaceAllStringFunc(message, func(match string) string {
		base := filepath.Base(match)
		if base == "" || base == "." || base == "/" {
			return "[redacted]"
		}
		return "[redacted]/" + base
	})
}
