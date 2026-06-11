package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/agent"
	"github.com/kernel-guard/bpfcompat/internal/cloudregistry"
	"github.com/kernel-guard/bpfcompat/internal/manifest"
	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/internal/runtime"
)

const (
	agentRegistryTokenEnv     = "BPFCOMPAT_AGENT_REGISTRY_TOKEN"
	agentIdentityTokenEnv     = "BPFCOMPAT_AGENT_IDENTITY_TOKEN"
	agentLoadPolicyPathEnv    = "BPFCOMPAT_AGENT_LOAD_POLICY_PATH"
	agentRequireLoadPolicyEnv = "BPFCOMPAT_AGENT_REQUIRE_LOAD_POLICY"
	agentExpectedDecisionEnv  = "BPFCOMPAT_AGENT_EXPECTED_DECISION_ID"
	agentExpectedSHA256Env    = "BPFCOMPAT_AGENT_EXPECTED_SHA256"
	agentRequirePinsEnv       = "BPFCOMPAT_AGENT_REQUIRE_APPROVAL_PINS"
	agentRequireManifestEnv   = "BPFCOMPAT_AGENT_REQUIRE_MANIFEST"
	agentIdentityHeader       = "X-API-Identity-Token"
	agentFetchMaxBytes        = 128 << 20

	agentLastResultPathEnv     = "BPFCOMPAT_AGENT_LAST_RESULT_PATH"
	defaultAgentLastResultPath = "/var/lib/bpfcompat-agent/last-apply.json"
	agentStatusSchemaVersion   = "agent_status.v0.1"
)

type agentCommonFlags struct {
	workDir                *string
	apiURL                 *string
	tenant                 *string
	project                *string
	agentID                *string
	artifactName           *string
	version                *string
	targetProfile          *string
	registryToken          *string
	identityToken          *string
	requireVerifiedHistory *bool
	relaxedPolicy          *bool
	outPath                *string
	probe                  runtimeProbeArgs
	policy                 runtimePolicyArgs
}

type agentPlanEnvelope struct {
	Decision  agent.DecisionResult           `json:"decision"`
	HostProbe runtime.HostCapabilities       `json:"host_probe"`
	Audit     *runtime.DecisionPersistResult `json:"audit,omitempty"`
}

type agentApplyResultFile struct {
	SchemaVersion   string                         `json:"schema_version,omitempty"`
	Phase           string                         `json:"phase,omitempty"`
	Error           string                         `json:"error,omitempty"`
	CreatedAt       string                         `json:"created_at,omitempty"`
	Decision        agent.DecisionResult           `json:"decision"`
	HostProbe       runtime.HostCapabilities       `json:"host_probe"`
	Fetch           runtime.FetchResult            `json:"fetch"`
	PlanAudit       *runtime.DecisionPersistResult `json:"plan_audit,omitempty"`
	ApprovalPins    *agentApprovalPins             `json:"approval_pins,omitempty"`
	ManifestIntent  *agentManifestIntent           `json:"manifest_intent,omitempty"`
	LoadPolicy      *agent.LoadPolicyDecision      `json:"load_policy,omitempty"`
	LoadLedger      *agent.LoadLedgerEntry         `json:"load_ledger,omitempty"`
	LoadLedgerPath  string                         `json:"load_ledger_path,omitempty"`
	LoadLedgerError string                         `json:"load_ledger_error,omitempty"`
	Execution       *runtime.ExecuteResult         `json:"execution,omitempty"`
	LoadSkipped     string                         `json:"load_skipped,omitempty"`
	Audit           *runtime.DecisionPersistResult `json:"audit,omitempty"`
	AuditError      string                         `json:"audit_error,omitempty"`
}

type agentApprovalPins struct {
	Required           bool   `json:"required"`
	ExpectedDecisionID string `json:"expected_decision_id,omitempty"`
	ExpectedSHA256     string `json:"expected_sha256,omitempty"`
	Verified           bool   `json:"verified"`
}

type agentManifestIntent struct {
	Required     bool   `json:"required"`
	Path         string `json:"path,omitempty"`
	ProgramCount int    `json:"program_count,omitempty"`
	Valid        bool   `json:"valid"`
}

type agentStatusSummary struct {
	SchemaVersion         string `json:"schema_version"`
	Healthy               bool   `json:"healthy"`
	SourcePath            string `json:"source_path"`
	UpdatedAt             string `json:"updated_at,omitempty"`
	AgentID               string `json:"agent_id,omitempty"`
	ArtifactName          string `json:"artifact_name,omitempty"`
	SelectedVersion       string `json:"selected_version,omitempty"`
	SelectedSHA256        string `json:"selected_sha256,omitempty"`
	TargetProfile         string `json:"target_profile,omitempty"`
	DecisionID            string `json:"decision_id,omitempty"`
	FetchStatus           string `json:"fetch_status"`
	FetchOutputPath       string `json:"fetch_output_path,omitempty"`
	LoadApproved          bool   `json:"load_approved"`
	LoadStatus            string `json:"load_status"`
	LoadPolicyStatus      string `json:"load_policy_status,omitempty"`
	LoadPolicyRule        string `json:"load_policy_rule,omitempty"`
	AuditStatus           string `json:"audit_status"`
	AuditTracePath        string `json:"audit_trace_path,omitempty"`
	LoadLedgerPath        string `json:"load_ledger_path,omitempty"`
	PreviousLoadedVersion string `json:"previous_loaded_version,omitempty"`
	RollbackHint          string `json:"rollback_hint,omitempty"`
	LastError             string `json:"last_error,omitempty"`
	LastErrorPhase        string `json:"last_error_phase,omitempty"`
	HistoryVerified       *bool  `json:"history_verified,omitempty"`
	RequiredPassed        int    `json:"required_passed"`
	RequiredFailed        int    `json:"required_failed"`
	SummaryStatus         string `json:"summary_status,omitempty"`
	HostProfileHint       string `json:"host_profile_hint,omitempty"`
	CandidatesReviewed    int    `json:"candidates_reviewed,omitempty"`
	CandidatesAccepted    int    `json:"candidates_accepted,omitempty"`
}

type agentRollbackPlan struct {
	SchemaVersion   string                 `json:"schema_version"`
	Status          string                 `json:"status"`
	ArtifactName    string                 `json:"artifact_name"`
	Current         agent.LoadLedgerEntry  `json:"current"`
	Previous        *agent.LoadLedgerEntry `json:"previous,omitempty"`
	RollbackCommand []string               `json:"rollback_command,omitempty"`
	RecordedLedger  *agent.LoadLedgerEntry `json:"recorded_ledger,omitempty"`
	LoadLedgerPath  string                 `json:"load_ledger_path,omitempty"`
	Reason          string                 `json:"reason,omitempty"`
}

type agentUnloadPlan struct {
	SchemaVersion  string                 `json:"schema_version"`
	Status         string                 `json:"status"`
	ArtifactName   string                 `json:"artifact_name,omitempty"`
	PinPath        string                 `json:"pin_path,omitempty"`
	Executed       bool                   `json:"executed"`
	Removed        bool                   `json:"removed"`
	LoadLedger     *agent.LoadLedgerEntry `json:"load_ledger,omitempty"`
	LoadLedgerPath string                 `json:"load_ledger_path,omitempty"`
	Reason         string                 `json:"reason,omitempty"`
}

type agentRevocationDrillResult struct {
	SchemaVersion  string                   `json:"schema_version"`
	Status         string                   `json:"status"`
	AgentID        string                   `json:"agent_id"`
	PolicyPath     string                   `json:"policy_path"`
	Decision       agent.LoadPolicyDecision `json:"decision"`
	LoadLedger     *agent.LoadLedgerEntry   `json:"load_ledger,omitempty"`
	LoadLedgerPath string                   `json:"load_ledger_path,omitempty"`
}

type agentPreflightResult struct {
	SchemaVersion string                `json:"schema_version"`
	Status        string                `json:"status"`
	CreatedAt     string                `json:"created_at"`
	AgentID       string                `json:"agent_id"`
	WorkDir       string                `json:"workdir"`
	OutDir        string                `json:"out_dir,omitempty"`
	Checks        []agentPreflightCheck `json:"checks"`
}

type agentPreflightCheck struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Required bool   `json:"required"`
	Detail   string `json:"detail,omitempty"`
	Error    string `json:"error,omitempty"`
}

func runAgent(args []string) int {
	if len(args) == 0 {
		printAgentUsage()
		return runner.ExitToolError
	}
	switch args[0] {
	case "-h", "--help", "help":
		printAgentUsage()
		return 0
	case "preflight":
		return runAgentPreflight(args[1:])
	case "plan":
		return runAgentPlan(args[1:])
	case "apply":
		return runAgentApply(args[1:])
	case "status":
		return runAgentStatus(args[1:])
	case "ledger":
		return runAgentLedger(args[1:])
	case "rollback":
		return runAgentRollback(args[1:])
	case "unload":
		return runAgentUnload(args[1:])
	case "revocation-drill":
		return runAgentRevocationDrill(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown agent subcommand: %s\n\n", args[0])
		printAgentUsage()
		return runner.ExitToolError
	}
}

func addAgentCommonFlags(fs *flag.FlagSet) agentCommonFlags {
	flags := agentCommonFlags{
		workDir:                fs.String("workdir", ".bpfcompat", "Working directory root for local registry/audit"),
		apiURL:                 fs.String("api-url", "", "Control-plane base URL for remote agent decision (optional)"),
		tenant:                 fs.String("tenant", "", "Cloud registry tenant for remote/project decisions"),
		project:                fs.String("project", "", "Cloud registry project for remote/project decisions"),
		agentID:                fs.String("agent-id", "", "Stable agent identity label (defaults to hostname)"),
		artifactName:           fs.String("artifact-name", "", "Artifact family name"),
		version:                fs.String("version", "", "Requested artifact version (optional)"),
		targetProfile:          fs.String("target-profile", "", "Explicit target profile hint (optional)"),
		registryToken:          fs.String("registry-token", "", "Registry bearer token (or BPFCOMPAT_AGENT_REGISTRY_TOKEN)"),
		identityToken:          fs.String("identity-token", "", "Optional identity JWT (or BPFCOMPAT_AGENT_IDENTITY_TOKEN)"),
		requireVerifiedHistory: fs.Bool("require-verified-history", true, "Require signed artifact-history verification before accepting a decision"),
		relaxedPolicy:          fs.Bool("relaxed-policy", false, "Disable agent default strict selector policy"),
		outPath:                fs.String("out", "", "Write JSON result to file (optional)"),
	}
	flags.probe = addRuntimeProbeFlags(fs)
	flags.policy = addRuntimePolicyFlags(fs)
	return flags
}

func runAgentPreflight(args []string) int {
	fs := flag.NewFlagSet("agent preflight", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	outDir := fs.String("out-dir", "artifacts/agent-selected", "Directory where selected artifacts are written")
	apiURL := fs.String("api-url", "", "Control-plane base URL to validate when provided")
	tenant := fs.String("tenant", "", "Cloud registry tenant to validate when provided")
	project := fs.String("project", "", "Cloud registry project to validate when provided")
	artifactName := fs.String("artifact-name", "", "Artifact family name to validate when provided")
	agentID := fs.String("agent-id", "", "Stable agent identity label (defaults to hostname)")
	registryToken := fs.String("registry-token", "", "Registry bearer token (or BPFCOMPAT_AGENT_REGISTRY_TOKEN)")
	loadPolicyPath := fs.String("load-policy", strings.TrimSpace(os.Getenv(agentLoadPolicyPathEnv)), "Local agent load policy path for reviewed host-load preflight")
	requireLoadPolicy := fs.Bool("require-load-policy", boolEnvDefault(agentRequireLoadPolicyEnv, true), "Require a local load policy when --include-load is set")
	expectedDecisionID := fs.String("expected-decision-id", strings.TrimSpace(os.Getenv(agentExpectedDecisionEnv)), "Reviewed agent decision id expected during approved host load")
	expectedSHA256 := fs.String("expected-sha256", strings.TrimSpace(os.Getenv(agentExpectedSHA256Env)), "Reviewed selected artifact SHA-256 expected during approved host load")
	requireApprovalPins := fs.Bool("require-approval-pins", boolEnvDefault(agentRequirePinsEnv, false), "Require expected decision id and SHA-256 when --include-load is set")
	manifestPath := fs.String("manifest", "", "Manifest path expected during approved host load")
	requireManifest := fs.Bool("require-manifest", boolEnvDefault(agentRequireManifestEnv, false), "Require a valid manifest when --include-load is set")
	validatorPath := fs.String("validator", "", "Validator binary override path for reviewed host-load preflight")
	includeLoad := fs.Bool("include-load", false, "Also verify reviewed host-load prerequisites")
	requireConfig := fs.Bool("require-config", false, "Require api-url, tenant, project, artifact-name, and registry token")
	checkHostProbe := fs.Bool("check-host-probe", true, "Probe host capabilities during preflight")
	asJSON := fs.Bool("json", false, "Print preflight as JSON")
	outPath := fs.String("out", "", "Write preflight JSON to file (optional)")
	probeFlags := addRuntimeProbeFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat agent preflight [--workdir DIR --out-dir DIR] [--include-load --load-policy path] [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}

	result := buildAgentPreflight(agentPreflightOptions{
		WorkDir:            *workDir,
		OutDir:             *outDir,
		APIURL:             *apiURL,
		Tenant:             *tenant,
		Project:            *project,
		ArtifactName:       *artifactName,
		AgentID:            *agentID,
		RegistryToken:      agentRegistryToken(*registryToken),
		LoadPolicyPath:     *loadPolicyPath,
		RequireLoadPolicy:  *requireLoadPolicy,
		ExpectedDecisionID: *expectedDecisionID,
		ExpectedSHA256:     *expectedSHA256,
		RequirePins:        *requireApprovalPins,
		ManifestPath:       *manifestPath,
		RequireManifest:    *requireManifest,
		ValidatorPath:      *validatorPath,
		IncludeLoad:        *includeLoad,
		RequireConfig:      *requireConfig,
		CheckHostProbe:     *checkHostProbe,
		ProbeOptions:       probeFlags.BuildProbeOptions(),
	})
	if strings.TrimSpace(*outPath) != "" {
		if err := writeAgentJSONFile(*outPath, result); err != nil {
			fmt.Fprintf(os.Stderr, "write agent preflight: %v\n", err)
			return runner.ExitToolError
		}
	}
	if *asJSON {
		if err := writeAgentJSON("", result); err != nil {
			fmt.Fprintf(os.Stderr, "write agent preflight: %v\n", err)
			return runner.ExitToolError
		}
	} else {
		printAgentPreflight(result)
	}
	if result.Status != "pass" {
		return runner.ExitToolError
	}
	return runner.ExitSuccess
}

type agentPreflightOptions struct {
	WorkDir            string
	OutDir             string
	APIURL             string
	Tenant             string
	Project            string
	ArtifactName       string
	AgentID            string
	RegistryToken      string
	LoadPolicyPath     string
	RequireLoadPolicy  bool
	ExpectedDecisionID string
	ExpectedSHA256     string
	RequirePins        bool
	ManifestPath       string
	RequireManifest    bool
	ValidatorPath      string
	IncludeLoad        bool
	RequireConfig      bool
	CheckHostProbe     bool
	ProbeOptions       runtime.ProbeOptions
}

func buildAgentPreflight(opts agentPreflightOptions) agentPreflightResult {
	workDir := strings.TrimSpace(opts.WorkDir)
	if workDir == "" {
		workDir = ".bpfcompat"
	}
	outDir := strings.TrimSpace(opts.OutDir)
	if outDir == "" {
		outDir = "artifacts/agent-selected"
	}
	result := agentPreflightResult{
		SchemaVersion: "agent_preflight.v0.1",
		Status:        "pass",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		AgentID:       resolveAgentID(opts.AgentID),
		WorkDir:       filepath.Clean(workDir),
		OutDir:        filepath.Clean(outDir),
	}
	add := func(check agentPreflightCheck) {
		if check.Status == "" {
			check.Status = "pass"
		}
		result.Checks = append(result.Checks, check)
		if check.Required && check.Status != "pass" {
			result.Status = "fail"
		}
	}

	add(agentPreflightCheck{
		Name:     "agent_identity",
		Status:   "pass",
		Required: true,
		Detail:   result.AgentID,
	})

	if err := checkWritableDirectory(workDir); err != nil {
		add(agentPreflightCheck{Name: "workdir_writable", Status: "fail", Required: true, Detail: filepath.Clean(workDir), Error: err.Error()})
	} else {
		add(agentPreflightCheck{Name: "workdir_writable", Status: "pass", Required: true, Detail: filepath.Clean(workDir)})
	}
	if err := checkWritableDirectory(outDir); err != nil {
		add(agentPreflightCheck{Name: "out_dir_writable", Status: "fail", Required: true, Detail: filepath.Clean(outDir), Error: err.Error()})
	} else {
		add(agentPreflightCheck{Name: "out_dir_writable", Status: "pass", Required: true, Detail: filepath.Clean(outDir)})
	}

	checkAgentConfigPreflight(opts, add)

	if opts.CheckHostProbe {
		probe, err := runtime.ProbeHostCapabilitiesWithOptions(opts.ProbeOptions)
		if err != nil {
			add(agentPreflightCheck{Name: "host_probe", Status: "fail", Required: true, Error: err.Error()})
		} else {
			add(agentPreflightCheck{Name: "host_probe", Status: "pass", Required: true, Detail: runtime.HostProfileHint(probe)})
		}
	} else {
		add(agentPreflightCheck{Name: "host_probe", Status: "skip", Required: false, Detail: "disabled by --check-host-probe=false"})
	}

	loadPolicyPath := strings.TrimSpace(opts.LoadPolicyPath)
	switch {
	case opts.IncludeLoad && opts.RequireLoadPolicy && loadPolicyPath == "":
		add(agentPreflightCheck{Name: "load_policy", Status: "fail", Required: true, Error: "--load-policy is required when --include-load is set"})
	case loadPolicyPath != "":
		policy, err := agent.LoadLoadPolicy(loadPolicyPath)
		if err != nil {
			add(agentPreflightCheck{Name: "load_policy", Status: "fail", Required: opts.IncludeLoad, Detail: filepath.Clean(loadPolicyPath), Error: err.Error()})
		} else {
			add(agentPreflightCheck{Name: "load_policy", Status: "pass", Required: opts.IncludeLoad, Detail: fmt.Sprintf("%s default=%s rules=%d", filepath.Clean(loadPolicyPath), policy.DefaultAction, len(policy.Rules))})
		}
	default:
		add(agentPreflightCheck{Name: "load_policy", Status: "skip", Required: false, Detail: "not required for fetch-only preflight"})
	}

	checkAgentApprovalPinsPreflight(opts, add)
	checkAgentManifestPreflight(opts, add)

	if opts.IncludeLoad || strings.TrimSpace(opts.ValidatorPath) != "" || strings.TrimSpace(os.Getenv("BPFCOMPAT_VALIDATOR_BIN")) != "" {
		path, err := resolveAgentValidatorBinary(opts.ValidatorPath)
		if err != nil {
			add(agentPreflightCheck{Name: "validator_binary", Status: "fail", Required: opts.IncludeLoad, Error: err.Error()})
		} else {
			add(agentPreflightCheck{Name: "validator_binary", Status: "pass", Required: opts.IncludeLoad, Detail: path})
		}
	} else {
		add(agentPreflightCheck{Name: "validator_binary", Status: "skip", Required: false, Detail: "not required for fetch-only preflight"})
	}

	return result
}

func checkAgentConfigPreflight(opts agentPreflightOptions, add func(agentPreflightCheck)) {
	required := opts.RequireConfig
	var errorsOut []string
	apiURL := strings.TrimSpace(opts.APIURL)
	if apiURL != "" {
		if _, err := resolveAgentEndpoint(apiURL); err != nil {
			errorsOut = append(errorsOut, err.Error())
		}
	} else if required {
		errorsOut = append(errorsOut, "--api-url is required")
	}
	tenant := strings.TrimSpace(opts.Tenant)
	project := strings.TrimSpace(opts.Project)
	switch {
	case tenant == "" && project == "":
		if required {
			errorsOut = append(errorsOut, "--tenant and --project are required")
		}
	case tenant == "" || project == "":
		errorsOut = append(errorsOut, "--tenant and --project must be provided together")
	}
	if strings.TrimSpace(opts.ArtifactName) == "" && required {
		errorsOut = append(errorsOut, "--artifact-name is required")
	}
	if strings.TrimSpace(opts.RegistryToken) == "" && required {
		errorsOut = append(errorsOut, "registry token is required; set --registry-token or "+agentRegistryTokenEnv)
	}
	if len(errorsOut) > 0 {
		add(agentPreflightCheck{Name: "agent_config", Status: "fail", Required: required, Error: strings.Join(errorsOut, "; ")})
		return
	}
	details := []string{}
	if apiURL != "" {
		details = append(details, "api_url="+apiURL)
	}
	if tenant != "" || project != "" {
		details = append(details, "project="+tenant+"/"+project)
	}
	if strings.TrimSpace(opts.ArtifactName) != "" {
		details = append(details, "artifact="+strings.TrimSpace(opts.ArtifactName))
	}
	if strings.TrimSpace(opts.RegistryToken) != "" {
		details = append(details, "registry_token=configured")
	}
	if len(details) == 0 {
		details = append(details, "not required")
	}
	add(agentPreflightCheck{Name: "agent_config", Status: "pass", Required: required, Detail: strings.Join(details, " ")})
}

func checkAgentApprovalPinsPreflight(opts agentPreflightOptions, add func(agentPreflightCheck)) {
	if !opts.IncludeLoad {
		add(agentPreflightCheck{Name: "approval_pins", Status: "skip", Required: false, Detail: "not required for fetch-only preflight"})
		return
	}
	required := opts.RequirePins
	expectedDecisionID := strings.TrimSpace(opts.ExpectedDecisionID)
	expectedSHA256 := strings.TrimSpace(opts.ExpectedSHA256)
	var errorsOut []string
	if required && expectedDecisionID == "" {
		errorsOut = append(errorsOut, "--expected-decision-id is required")
	}
	if required && expectedSHA256 == "" {
		errorsOut = append(errorsOut, "--expected-sha256 is required")
	}
	if expectedSHA256 != "" && !isAgentSHA256Hex(expectedSHA256) {
		errorsOut = append(errorsOut, "--expected-sha256 must be 64 hex characters")
	}
	if len(errorsOut) > 0 {
		add(agentPreflightCheck{Name: "approval_pins", Status: "fail", Required: required, Error: strings.Join(errorsOut, "; ")})
		return
	}
	detail := "not configured"
	if expectedDecisionID != "" || expectedSHA256 != "" {
		parts := []string{}
		if expectedDecisionID != "" {
			parts = append(parts, "decision_id=configured")
		}
		if expectedSHA256 != "" {
			parts = append(parts, "sha256=configured")
		}
		detail = strings.Join(parts, " ")
	}
	add(agentPreflightCheck{Name: "approval_pins", Status: "pass", Required: required, Detail: detail})
}

func checkAgentManifestPreflight(opts agentPreflightOptions, add func(agentPreflightCheck)) {
	if !opts.IncludeLoad {
		add(agentPreflightCheck{Name: "manifest_intent", Status: "skip", Required: false, Detail: "not required for fetch-only preflight"})
		return
	}
	required := opts.RequireManifest
	manifestPath := strings.TrimSpace(opts.ManifestPath)
	if required && manifestPath == "" {
		add(agentPreflightCheck{Name: "manifest_intent", Status: "fail", Required: true, Error: "--manifest is required when --require-manifest=true"})
		return
	}
	if manifestPath == "" {
		add(agentPreflightCheck{Name: "manifest_intent", Status: "skip", Required: false, Detail: "not configured"})
		return
	}
	if _, err := loadAgentManifestIntent(manifestPath); err != nil {
		add(agentPreflightCheck{Name: "manifest_intent", Status: "fail", Required: required, Detail: filepath.Clean(manifestPath), Error: err.Error()})
		return
	}
	add(agentPreflightCheck{Name: "manifest_intent", Status: "pass", Required: required, Detail: filepath.Clean(manifestPath)})
}

func checkWritableDirectory(path string) error {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" {
		return fmt.Errorf("directory path is empty")
	}
	if err := os.MkdirAll(cleanPath, 0o755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	f, err := os.CreateTemp(cleanPath, ".bpfcompat-preflight-*")
	if err != nil {
		return fmt.Errorf("create probe file: %w", err)
	}
	name := f.Name()
	if _, err := f.Write([]byte("ok\n")); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return fmt.Errorf("write probe file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close probe file: %w", err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove probe file: %w", err)
	}
	return nil
}

func resolveAgentValidatorBinary(pathText string) (string, error) {
	candidates := []string{}
	if strings.TrimSpace(pathText) != "" {
		candidates = append(candidates, strings.TrimSpace(pathText))
	}
	if envPath := strings.TrimSpace(os.Getenv("BPFCOMPAT_VALIDATOR_BIN")); envPath != "" {
		candidates = append(candidates, envPath)
	}
	candidates = append(candidates,
		"/usr/libexec/bpfcompat/bpfcompat-validator",
		"/usr/local/libexec/bpfcompat/bpfcompat-validator",
		"validator/c-libbpf/bin/bpfcompat-validator",
	)
	var lastErr error
	for _, candidate := range candidates {
		resolved, err := filepath.Abs(filepath.Clean(candidate))
		if err != nil {
			lastErr = err
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil {
			lastErr = err
			continue
		}
		if info.IsDir() {
			lastErr = fmt.Errorf("%s is a directory", resolved)
			continue
		}
		if info.Mode()&0o111 == 0 {
			lastErr = fmt.Errorf("%s is not executable", resolved)
			continue
		}
		return resolved, nil
	}
	if lastErr != nil {
		return "", fmt.Errorf("validator binary not found or unusable: %w", lastErr)
	}
	return "", fmt.Errorf("validator binary not found")
}

func printAgentPreflight(result agentPreflightResult) {
	fmt.Printf("Agent preflight: %s agent=%s\n", result.Status, result.AgentID)
	for _, check := range result.Checks {
		required := "optional"
		if check.Required {
			required = "required"
		}
		fmt.Printf("  - %s: %s (%s)", check.Name, check.Status, required)
		if check.Detail != "" {
			fmt.Printf(" %s", check.Detail)
		}
		if check.Error != "" {
			fmt.Printf(" error=%s", check.Error)
		}
		fmt.Println()
	}
}

func runAgentPlan(args []string) int {
	fs := flag.NewFlagSet("agent plan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	flags := addAgentCommonFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat agent plan --artifact-name <name> [--api-url URL --tenant T --project P] [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}

	envelope, _, _, err := executeAgentPlan(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent plan failed: %v\n", err)
		return runner.ExitToolError
	}
	if err := writeAgentJSON(*flags.outPath, envelope); err != nil {
		fmt.Fprintf(os.Stderr, "write agent plan: %v\n", err)
		return runner.ExitToolError
	}
	fmt.Printf("Agent decision: %s selected %s@%s\n",
		envelope.Decision.DecisionID,
		envelope.Decision.SelectedArtifact.Name,
		envelope.Decision.SelectedArtifact.Version,
	)
	return runner.ExitSuccess
}

func runAgentApply(args []string) int {
	fs := flag.NewFlagSet("agent apply", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	flags := addAgentCommonFlags(fs)
	outDir := fs.String("out-dir", "artifacts/agent-selected", "Directory to write selected artifact")
	approveLoad := fs.Bool("approve-load", false, "Explicitly approve host load after plan/fetch verification")
	manifestPath := fs.String("manifest", "", "Manifest path override for host load (optional)")
	attachMode := fs.String("attach-mode", "best-effort", "Attach mode for approved host load (disabled|best-effort|required)")
	probeFeatures := fs.Bool("probe-features", true, "Enable validator capability probing during approved host load")
	useSudo := fs.Bool("use-sudo", true, "Run validator with sudo during approved host load")
	sudoNonInteractive := fs.Bool("sudo-non-interactive", true, "Use sudo -n during approved host load")
	validatorPath := fs.String("validator", "", "Validator binary override path")
	timeoutText := fs.String("timeout", "2m", "Approved host load timeout")
	loadPolicyPath := fs.String("load-policy", strings.TrimSpace(os.Getenv(agentLoadPolicyPathEnv)), "Local agent load policy path required before approved host load")
	requireLoadPolicy := fs.Bool("require-load-policy", boolEnvDefault(agentRequireLoadPolicyEnv, true), "Require --load-policy before approved host load")
	expectedDecisionID := fs.String("expected-decision-id", strings.TrimSpace(os.Getenv(agentExpectedDecisionEnv)), "Reviewed agent decision id required to match before approved host load")
	expectedSHA256 := fs.String("expected-sha256", strings.TrimSpace(os.Getenv(agentExpectedSHA256Env)), "Reviewed selected artifact SHA-256 required to match before approved host load")
	requireApprovalPins := fs.Bool("require-approval-pins", boolEnvDefault(agentRequirePinsEnv, false), "Require both --expected-decision-id and --expected-sha256 before approved host load")
	requireManifest := fs.Bool("require-manifest", boolEnvDefault(agentRequireManifestEnv, false), "Require a valid manifest before approved host load")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat agent apply --artifact-name <name> [--api-url URL --tenant T --project P] [--approve-load] [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}

	timeout, err := time.ParseDuration(strings.TrimSpace(*timeoutText))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --timeout value %q: %v\n", *timeoutText, err)
		writeAgentFailureJSON(*flags.outPath, "parse_timeout", err)
		return runner.ExitToolError
	}
	envelope, selectedRecord, remote, err := executeAgentPlan(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent apply plan failed: %v\n", err)
		writeAgentFailureJSON(*flags.outPath, "plan", err)
		return runner.ExitToolError
	}

	fetchResult, err := fetchAgentSelectedArtifact(
		selectedRecord,
		envelope.Decision.SelectedArtifact,
		remote,
		*flags.apiURL,
		agentRegistryToken(*flags.registryToken),
		agentIdentityToken(*flags.identityToken),
		*outDir,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent fetch failed: %v\n", err)
		writeAgentFailureJSON(*flags.outPath, "fetch", err)
		return runner.ExitToolError
	}
	payload := agentApplyResultFile{
		Decision:  envelope.Decision,
		HostProbe: envelope.HostProbe,
		Fetch:     fetchResult,
	}
	if envelope.Audit != nil {
		payload.PlanAudit = envelope.Audit
	}

	trace := runtime.DecisionTrace{
		DecisionID:       envelope.Decision.DecisionID,
		Source:           "agent",
		Operation:        "fetch",
		ArtifactName:     envelope.Decision.ArtifactName,
		RequestedVersion: envelope.Decision.RequestedVersion,
		TargetProfileID:  envelope.Decision.TargetProfile,
		Policy:           envelope.Decision.Policy,
		HostProbe:        &envelope.HostProbe,
		Selection:        &envelope.Decision.Selection,
		Fetch:            &fetchResult,
		Status:           "success",
		Notes: []string{
			"agent apply fetched and verified selected artifact",
			fmt.Sprintf("approve_load=%t", *approveLoad),
		},
	}

	if *approveLoad {
		payload.ApprovalPins = buildAgentApprovalPins(*expectedDecisionID, *expectedSHA256, *requireApprovalPins, false)
		if err := validateAgentApprovalPins(envelope.Decision, fetchResult, *expectedDecisionID, *expectedSHA256, *requireApprovalPins); err != nil {
			err := fmt.Errorf("agent approval pinning failed: %w", err)
			payload.Phase = "approval"
			payload.Error = err.Error()
			trace.Operation = "execute"
			trace.Status = "error"
			trace.Error = err.Error()
			persistAgentApplyAuditAndLedger(*flags.workDir, &payload, trace, "load", "denied", err.Error())
			if writeErr := writeAgentJSON(*flags.outPath, payload); writeErr != nil {
				fmt.Fprintf(os.Stderr, "write agent apply result: %v\n", writeErr)
			}
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return runner.ExitToolError
		}
		if payload.ApprovalPins != nil {
			payload.ApprovalPins.Verified = true
		}
		envelope.Decision.LoadApproved = true
		payload.Decision = envelope.Decision
		manifestToUse := strings.TrimSpace(*manifestPath)
		if manifestToUse == "" && !remote {
			manifestToUse = strings.TrimSpace(selectedRecord.ManifestPath)
		}
		manifestIntent, err := buildAgentManifestIntent(manifestToUse, *requireManifest)
		payload.ManifestIntent = &manifestIntent
		if err != nil {
			err := fmt.Errorf("agent manifest intent failed: %w", err)
			payload.Phase = "manifest"
			payload.Error = err.Error()
			trace.Operation = "execute"
			trace.Status = "error"
			trace.Error = err.Error()
			persistAgentApplyAuditAndLedger(*flags.workDir, &payload, trace, "load", "denied", err.Error())
			if writeErr := writeAgentJSON(*flags.outPath, payload); writeErr != nil {
				fmt.Fprintf(os.Stderr, "write agent apply result: %v\n", writeErr)
			}
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return runner.ExitToolError
		}
		policyDecision, policyErr := evaluateAgentLocalLoadPolicy(
			strings.TrimSpace(*loadPolicyPath),
			*requireLoadPolicy,
			envelope.Decision,
			selectedRecord,
			envelope.HostProbe,
			manifestToUse,
		)
		if policyDecision.SchemaVersion != "" {
			payload.LoadPolicy = &policyDecision
			trace.Notes = append(trace.Notes, fmt.Sprintf("local load policy: %s:%s", policyDecision.RuleName, policyDecision.Action))
		}
		if policyErr != nil {
			err := fmt.Errorf("agent local load policy failed: %w", policyErr)
			payload.Phase = "load_policy"
			payload.Error = err.Error()
			trace.Operation = "execute"
			trace.Status = "error"
			trace.Error = err.Error()
			persistAgentApplyAuditAndLedger(*flags.workDir, &payload, trace, "load", "denied", err.Error())
			if writeErr := writeAgentJSON(*flags.outPath, payload); writeErr != nil {
				fmt.Fprintf(os.Stderr, "write agent apply result: %v\n", writeErr)
			}
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return runner.ExitToolError
		}
		if !policyDecision.Allowed {
			err := fmt.Errorf("agent local load policy denied: %s", policyDecision.Reason)
			payload.Phase = "load_policy"
			payload.Error = err.Error()
			trace.Operation = "execute"
			trace.Status = "error"
			trace.Error = err.Error()
			persistAgentApplyAuditAndLedger(*flags.workDir, &payload, trace, "load", "denied", err.Error())
			if writeErr := writeAgentJSON(*flags.outPath, payload); writeErr != nil {
				fmt.Fprintf(os.Stderr, "write agent apply result: %v\n", writeErr)
			}
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return runner.ExitToolError
		}
		execution, err := runtime.ExecuteArtifactOnHost(context.Background(), runtime.ExecuteRequest{
			ArtifactPath:        fetchResult.OutputPath,
			ManifestPath:        manifestToUse,
			AttachMode:          strings.TrimSpace(*attachMode),
			ProbeFeatures:       *probeFeatures,
			AllowHostLoad:       true,
			UseSudo:             *useSudo,
			SudoNonInteractive:  *sudoNonInteractive,
			ValidatorBinaryPath: strings.TrimSpace(*validatorPath),
			WorkDir:             *flags.workDir,
			Timeout:             timeout,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent approved load failed: %v\n", err)
			payload.Phase = "execute"
			payload.Error = err.Error()
			trace.Operation = "execute"
			trace.Status = "error"
			trace.Error = err.Error()
			persistAgentApplyAuditAndLedger(*flags.workDir, &payload, trace, "load", "error", err.Error())
			if writeErr := writeAgentJSON(*flags.outPath, payload); writeErr != nil {
				fmt.Fprintf(os.Stderr, "write agent apply result: %v\n", writeErr)
			}
			return runner.ExitToolError
		}
		payload.Execution = &execution
		trace.Operation = "execute"
		trace.Execution = &execution
		trace.Status = "success"
		if execution.Status != "pass" && execution.Status != "success" {
			trace.Status = "error"
			trace.Error = fmt.Sprintf("validator status=%s", execution.Status)
		}
	} else {
		payload.LoadSkipped = "host load requires --approve-load"
	}

	if *approveLoad {
		status := "pass"
		if payload.Execution != nil && payload.Execution.Status != "" {
			status = payload.Execution.Status
		}
		persistAgentApplyAuditAndLedger(*flags.workDir, &payload, trace, "load", status, "")
	} else {
		audit, auditErr := runtime.PersistDecisionTrace(*flags.workDir, trace)
		if auditErr != nil {
			payload.AuditError = auditErr.Error()
		} else {
			payload.Audit = &audit
		}
	}
	if err := writeAgentJSON(*flags.outPath, payload); err != nil {
		fmt.Fprintf(os.Stderr, "write agent apply result: %v\n", err)
		return runner.ExitToolError
	}
	if *approveLoad {
		status := ""
		if payload.Execution != nil {
			status = payload.Execution.Status
		}
		if status != "" && status != "pass" && status != "success" {
			fmt.Printf("Agent apply load failed: %s status=%s\n", fetchResult.OutputPath, status)
			return runner.ExitCompatibilityFailure
		}
		fmt.Printf("Agent apply loaded: %s\n", fetchResult.OutputPath)
	} else {
		fmt.Printf("Agent apply fetched: %s (load skipped; use --approve-load to load)\n", fetchResult.OutputPath)
	}
	return runner.ExitSuccess
}

func runAgentStatus(args []string) int {
	fs := flag.NewFlagSet("agent status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	statusPath := fs.String("path", defaultAgentLastResultPath, "Path to agent apply JSON result")
	asJSON := fs.Bool("json", false, "Print compact status as JSON")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat agent status [--path /var/lib/bpfcompat-agent/last-apply.json] [--json]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	summary, err := summarizeAgentStatus(resolveAgentStatusPath(*statusPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent status failed: %v\n", err)
		return runner.ExitToolError
	}
	if *asJSON {
		if err := writeAgentJSON("", summary); err != nil {
			fmt.Fprintf(os.Stderr, "write agent status: %v\n", err)
			return runner.ExitToolError
		}
	} else {
		printAgentStatus(summary)
	}
	if !summary.Healthy {
		return runner.ExitCompatibilityFailure
	}
	return runner.ExitSuccess
}

func runAgentLedger(args []string) int {
	fs := flag.NewFlagSet("agent ledger", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	artifactName := fs.String("artifact-name", "", "Filter by artifact family name")
	limit := fs.Int("limit", 20, "Maximum entries to print; 0 means all")
	asJSON := fs.Bool("json", false, "Print ledger entries as JSON")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat agent ledger [--workdir .bpfcompat] [--artifact-name name] [--limit 20] [--json]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	entries, err := agent.ListLoadLedgerEntries(*workDir, *artifactName, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent ledger failed: %v\n", err)
		return runner.ExitToolError
	}
	if *asJSON {
		if err := writeAgentJSON("", entries); err != nil {
			fmt.Fprintf(os.Stderr, "write agent ledger: %v\n", err)
			return runner.ExitToolError
		}
		return runner.ExitSuccess
	}
	for _, entry := range entries {
		fmt.Printf("%s %s %s %s@%s decision=%s",
			entry.CreatedAt,
			entry.Operation,
			entry.Status,
			entry.ArtifactName,
			entry.SelectedVersion,
			entry.DecisionID,
		)
		if entry.PreviousLoadedVersion != "" {
			fmt.Printf(" previous=%s", entry.PreviousLoadedVersion)
		}
		if entry.PolicyRule != "" {
			fmt.Printf(" policy=%s:%s", entry.PolicyRule, entry.PolicyAction)
		}
		if entry.Error != "" {
			fmt.Printf(" error=%s", entry.Error)
		}
		fmt.Println()
	}
	return runner.ExitSuccess
}

func runAgentRollback(args []string) int {
	fs := flag.NewFlagSet("agent rollback", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	apiURL := fs.String("api-url", "", "Control-plane base URL for execute mode (optional)")
	tenant := fs.String("tenant", "", "Cloud registry tenant for execute mode")
	project := fs.String("project", "", "Cloud registry project for execute mode")
	agentID := fs.String("agent-id", "", "Stable agent identity label")
	artifactName := fs.String("artifact-name", "", "Artifact family name")
	targetProfile := fs.String("target-profile", "", "Explicit target profile hint (optional)")
	registryToken := fs.String("registry-token", "", "Registry bearer token (or BPFCOMPAT_AGENT_REGISTRY_TOKEN)")
	identityToken := fs.String("identity-token", "", "Optional identity JWT (or BPFCOMPAT_AGENT_IDENTITY_TOKEN)")
	outDir := fs.String("out-dir", "artifacts/agent-selected", "Directory to write selected artifact in execute mode")
	outPath := fs.String("out", "", "Write rollback execution JSON result to file in execute mode")
	loadPolicyPath := fs.String("load-policy", strings.TrimSpace(os.Getenv(agentLoadPolicyPathEnv)), "Local agent load policy path required for execute mode")
	manifestPath := fs.String("manifest", "", "Manifest path override for execute mode")
	execute := fs.Bool("execute", false, "Execute rollback by loading the previous successful version")
	record := fs.Bool("record", true, "Append rollback drill record to the load ledger")
	asJSON := fs.Bool("json", false, "Print rollback plan as JSON")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat agent rollback --artifact-name <name> [--execute --load-policy path] [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	artifact := strings.TrimSpace(*artifactName)
	if artifact == "" {
		fmt.Fprintln(os.Stderr, "--artifact-name is required")
		return runner.ExitToolError
	}
	current, ok, err := agent.LastSuccessfulLoad(*workDir, artifact)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read rollback ledger: %v\n", err)
		return runner.ExitToolError
	}
	if !ok {
		fmt.Fprintf(os.Stderr, "no successful load found for %s\n", artifact)
		return runner.ExitToolError
	}

	plan := agentRollbackPlan{
		SchemaVersion: "agent_rollback_plan.v0.1",
		Status:        "ready",
		ArtifactName:  artifact,
		Current:       current,
	}
	if strings.TrimSpace(current.PreviousLoadedVersion) == "" {
		plan.Status = "blocked"
		plan.Reason = "current successful load has no previous successful version"
	} else {
		previous := agent.LoadLedgerEntry{
			ArtifactName:    artifact,
			SelectedVersion: current.PreviousLoadedVersion,
			SelectedSHA256:  current.PreviousLoadedSHA256,
			ArtifactPath:    current.PreviousLoadedArtifactPath,
			AgentID:         current.AgentID,
			Tenant:          current.Tenant,
			Project:         current.Project,
			TargetProfile:   firstNonEmpty(*targetProfile, current.TargetProfile),
			HostProfileHint: current.HostProfileHint,
			LoadApproved:    true,
		}
		plan.Previous = &previous
		plan.RollbackCommand = buildAgentRollbackApplyArgs(*apiURL, firstNonEmpty(*tenant, current.Tenant), firstNonEmpty(*project, current.Project), firstNonEmpty(*agentID, current.AgentID), artifact, previous.SelectedVersion, firstNonEmpty(*targetProfile, current.TargetProfile), agentRegistryToken(*registryToken), agentIdentityToken(*identityToken), *workDir, *outDir, *outPath, *loadPolicyPath, *manifestPath)
	}
	if *record {
		entry, ledgerPath, recordErr := recordAgentRollbackDrill(*workDir, plan)
		if recordErr != nil {
			fmt.Fprintf(os.Stderr, "record rollback drill: %v\n", recordErr)
			return runner.ExitToolError
		}
		plan.RecordedLedger = &entry
		plan.LoadLedgerPath = ledgerPath
	}
	if *execute {
		if plan.Status != "ready" || plan.Previous == nil {
			fmt.Fprintf(os.Stderr, "rollback is not ready: %s\n", plan.Reason)
			return runner.ExitToolError
		}
		return runAgentApply(rollbackExecuteArgs(plan.RollbackCommand, agentRegistryToken(*registryToken), agentIdentityToken(*identityToken)))
	}
	if *asJSON {
		if err := writeAgentJSON("", plan); err != nil {
			fmt.Fprintf(os.Stderr, "write rollback plan: %v\n", err)
			return runner.ExitToolError
		}
	} else {
		printAgentRollbackPlan(plan)
	}
	if plan.Status != "ready" {
		return runner.ExitCompatibilityFailure
	}
	return runner.ExitSuccess
}

func runAgentUnload(args []string) int {
	fs := flag.NewFlagSet("agent unload", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	artifactName := fs.String("artifact-name", "", "Artifact family name")
	pinPath := fs.String("pin-path", "", "Pinned BPF object path to unload/remove")
	execute := fs.Bool("execute", false, "Actually remove the pinned path")
	recursive := fs.Bool("recursive", false, "Allow recursive removal of a pinned directory")
	allowNonBPFFS := fs.Bool("allow-non-bpffs", false, "Allow non-/sys/fs/bpf paths for tests/labs")
	record := fs.Bool("record", true, "Append unload drill record to the load ledger")
	asJSON := fs.Bool("json", false, "Print unload plan as JSON")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat agent unload --pin-path /sys/fs/bpf/<pin> [--execute] [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	resolvedPin, err := resolveAgentUnloadPinPath(*pinPath, *allowNonBPFFS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent unload failed: %v\n", err)
		return runner.ExitToolError
	}
	plan := agentUnloadPlan{
		SchemaVersion: "agent_unload_plan.v0.1",
		Status:        "planned",
		ArtifactName:  strings.TrimSpace(*artifactName),
		PinPath:       resolvedPin,
		Executed:      *execute,
	}
	if *execute {
		removed, removeErr := removeAgentPinPath(resolvedPin, *recursive)
		plan.Removed = removed
		switch {
		case removeErr != nil:
			plan.Status = "error"
			plan.Reason = removeErr.Error()
		case removed:
			plan.Status = "pass"
		default:
			plan.Status = "absent"
			plan.Reason = "pin path was already absent"
		}
	}
	if *record {
		entry, ledgerPath, recordErr := recordAgentUnloadDrill(*workDir, plan)
		if recordErr != nil {
			fmt.Fprintf(os.Stderr, "record unload drill: %v\n", recordErr)
			return runner.ExitToolError
		}
		plan.LoadLedger = &entry
		plan.LoadLedgerPath = ledgerPath
	}
	if *asJSON {
		if err := writeAgentJSON("", plan); err != nil {
			fmt.Fprintf(os.Stderr, "write unload plan: %v\n", err)
			return runner.ExitToolError
		}
	} else {
		fmt.Printf("Agent unload: %s pin=%s executed=%t removed=%t\n", plan.Status, plan.PinPath, plan.Executed, plan.Removed)
		if plan.Reason != "" {
			fmt.Printf("Reason: %s\n", plan.Reason)
		}
	}
	if plan.Status == "error" {
		return runner.ExitToolError
	}
	return runner.ExitSuccess
}

func runAgentRevocationDrill(args []string) int {
	fs := flag.NewFlagSet("agent revocation-drill", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	policyPath := fs.String("load-policy", strings.TrimSpace(os.Getenv(agentLoadPolicyPathEnv)), "Local agent load policy path")
	agentID := fs.String("agent-id", "", "Agent identity to prove revoked")
	artifactName := fs.String("artifact-name", "", "Optional artifact family for ledger record")
	record := fs.Bool("record", true, "Append revocation drill record to the load ledger")
	asJSON := fs.Bool("json", false, "Print revocation drill as JSON")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat agent revocation-drill --agent-id <id> --load-policy path [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	id := resolveAgentID(*agentID)
	policy, err := agent.LoadLoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load revocation policy: %v\n", err)
		return runner.ExitToolError
	}
	decision := agent.EvaluateLoadPolicy(policy, agent.LoadPolicyContext{
		AgentID:      id,
		ArtifactName: strings.TrimSpace(*artifactName),
	})
	result := agentRevocationDrillResult{
		SchemaVersion: "agent_revocation_drill.v0.1",
		Status:        "fail",
		AgentID:       id,
		PolicyPath:    filepath.Clean(*policyPath),
		Decision:      decision,
	}
	if !decision.Allowed {
		result.Status = "pass"
	}
	if *record {
		entry, ledgerPath, recordErr := recordAgentRevocationDrill(*workDir, strings.TrimSpace(*artifactName), result)
		if recordErr != nil {
			fmt.Fprintf(os.Stderr, "record revocation drill: %v\n", recordErr)
			return runner.ExitToolError
		}
		result.LoadLedger = &entry
		result.LoadLedgerPath = ledgerPath
	}
	if *asJSON {
		if err := writeAgentJSON("", result); err != nil {
			fmt.Fprintf(os.Stderr, "write revocation drill: %v\n", err)
			return runner.ExitToolError
		}
	} else {
		fmt.Printf("Agent revocation drill: %s agent=%s decision=%s:%s\n", result.Status, result.AgentID, result.Decision.RuleName, result.Decision.Action)
	}
	if result.Status != "pass" {
		return runner.ExitCompatibilityFailure
	}
	return runner.ExitSuccess
}

func executeAgentPlan(flags agentCommonFlags) (agentPlanEnvelope, registry.ArtifactVersionRecord, bool, error) {
	artifactName := strings.TrimSpace(*flags.artifactName)
	if artifactName == "" {
		return agentPlanEnvelope{}, registry.ArtifactVersionRecord{}, false, fmt.Errorf("--artifact-name is required")
	}
	policy, err := flags.policy.BuildPolicy()
	if err != nil {
		return agentPlanEnvelope{}, registry.ArtifactVersionRecord{}, false, fmt.Errorf("invalid policy flags: %w", err)
	}
	if !*flags.relaxedPolicy {
		policy.RequireSummaryPass = true
		if policy.MaxRequiredFailed == nil {
			maxFailed := 0
			policy.MaxRequiredFailed = &maxFailed
		}
	}
	hostProbe, err := runtime.ProbeHostCapabilitiesWithOptions(flags.probe.BuildProbeOptions())
	if err != nil {
		return agentPlanEnvelope{}, registry.ArtifactVersionRecord{}, false, fmt.Errorf("runtime host probe failed: %w", err)
	}
	req := agent.DecisionRequest{
		Tenant:                 strings.TrimSpace(*flags.tenant),
		Project:                strings.TrimSpace(*flags.project),
		AgentID:                resolveAgentID(*flags.agentID),
		ArtifactName:           artifactName,
		Version:                strings.TrimSpace(*flags.version),
		TargetProfile:          strings.TrimSpace(*flags.targetProfile),
		Limit:                  5,
		RequireVerifiedHistory: flags.requireVerifiedHistory,
		Policy:                 policy,
		HostProbe:              hostProbe,
	}

	if strings.TrimSpace(*flags.apiURL) != "" {
		decision, err := requestRemoteAgentDecision(*flags.apiURL, req, agentRegistryToken(*flags.registryToken), agentIdentityToken(*flags.identityToken))
		if err != nil {
			return agentPlanEnvelope{}, registry.ArtifactVersionRecord{}, true, err
		}
		record := recordFromSelectedArtifact(decision.SelectedArtifact)
		return agentPlanEnvelope{Decision: decision, HostProbe: hostProbe}, record, true, nil
	}

	workDir := strings.TrimSpace(*flags.workDir)
	if workDir == "" {
		workDir = ".bpfcompat"
	}
	recordsWorkDir := workDir
	var records []registry.ArtifactVersionRecord
	if req.Tenant != "" || req.Project != "" {
		if req.Tenant == "" || req.Project == "" {
			return agentPlanEnvelope{}, registry.ArtifactVersionRecord{}, false, fmt.Errorf("--tenant and --project must be provided together for local cloud-registry decisions")
		}
		store := cloudregistry.NewStore(workDir)
		records, err = store.ListArtifactVersions(req.Tenant, req.Project, artifactName, 0)
		recordsWorkDir = agentRegistryProjectWorkDir(workDir, req.Tenant, req.Project)
	} else {
		records, err = registry.ListArtifactVersions(workDir, artifactName, 0)
	}
	if err != nil {
		return agentPlanEnvelope{}, registry.ArtifactVersionRecord{}, false, fmt.Errorf("read artifact history: %w", err)
	}
	decision, selectedRecord, err := agent.BuildDecision(recordsWorkDir, records, req)
	if err != nil {
		return agentPlanEnvelope{}, registry.ArtifactVersionRecord{}, false, err
	}
	trace := runtime.DecisionTrace{
		DecisionID:       decision.DecisionID,
		Source:           "agent",
		Operation:        "select",
		ArtifactName:     artifactName,
		RequestedVersion: req.Version,
		TargetProfileID:  req.TargetProfile,
		Policy:           decision.Policy,
		HostProbe:        &hostProbe,
		Selection:        &decision.Selection,
		Status:           "success",
		Notes:            []string{"agent plan does not load eBPF"},
	}
	audit, auditErr := runtime.PersistDecisionTrace(recordsWorkDir, trace)
	envelope := agentPlanEnvelope{Decision: decision, HostProbe: hostProbe}
	if auditErr == nil {
		envelope.Audit = &audit
	}
	return envelope, selectedRecord, false, nil
}

func evaluateAgentLocalLoadPolicy(
	policyPath string,
	requirePolicy bool,
	decision agent.DecisionResult,
	selectedRecord registry.ArtifactVersionRecord,
	hostProbe runtime.HostCapabilities,
	manifestPath string,
) (agent.LoadPolicyDecision, error) {
	if strings.TrimSpace(policyPath) == "" {
		if requirePolicy {
			return agent.LoadPolicyDecision{}, fmt.Errorf("--load-policy is required for --approve-load; set %s or pass --require-load-policy=false only in a controlled lab", agentLoadPolicyPathEnv)
		}
		return agent.LoadPolicyDecision{
			SchemaVersion: agent.LoadPolicySchemaVersion,
			Allowed:       true,
			RuleName:      "policy_not_configured",
			Action:        "allow",
			Reason:        "local load policy not configured and require_load_policy=false",
		}, nil
	}
	policy, err := agent.LoadLoadPolicy(policyPath)
	if err != nil {
		return agent.LoadPolicyDecision{}, err
	}
	var policyManifest *manifest.Manifest
	if strings.TrimSpace(manifestPath) != "" {
		loaded, err := manifest.Load(filepath.Clean(manifestPath))
		if err != nil {
			return agent.LoadPolicyDecision{}, fmt.Errorf("load policy manifest context: %w", err)
		}
		policyManifest = &loaded
	}
	historyVerified := false
	if decision.HistoryVerification != nil {
		historyVerified = decision.HistoryVerification.Verified
	}
	ctx := agent.LoadPolicyContext{
		AgentID:         decision.AgentID,
		Tenant:          decision.Tenant,
		Project:         decision.Project,
		ArtifactName:    firstNonEmpty(decision.SelectedArtifact.Name, decision.ArtifactName, selectedRecord.ArtifactName),
		TargetProfileID: decision.TargetProfile,
		SelectedRecord:  selectedRecord,
		HostProbe:       &hostProbe,
		HistoryVerified: historyVerified,
		Manifest:        policyManifest,
	}
	return agent.EvaluateLoadPolicy(policy, ctx), nil
}

func validateAgentApprovalPins(decision agent.DecisionResult, fetchResult runtime.FetchResult, expectedDecisionID, expectedSHA256 string, requirePins bool) error {
	expectedDecisionID = strings.TrimSpace(expectedDecisionID)
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	if requirePins {
		if expectedDecisionID == "" {
			return fmt.Errorf("--expected-decision-id is required when --require-approval-pins=true")
		}
		if expectedSHA256 == "" {
			return fmt.Errorf("--expected-sha256 is required when --require-approval-pins=true")
		}
	}
	if expectedDecisionID != "" && expectedDecisionID != strings.TrimSpace(decision.DecisionID) {
		return fmt.Errorf("decision id mismatch: expected=%s got=%s", expectedDecisionID, strings.TrimSpace(decision.DecisionID))
	}
	if expectedSHA256 != "" {
		if !isAgentSHA256Hex(expectedSHA256) {
			return fmt.Errorf("expected sha256 must be 64 lowercase/uppercase hex characters")
		}
		actual := strings.ToLower(firstNonEmpty(decision.SelectedArtifact.SHA256, fetchResult.ExpectedSHA256, fetchResult.ActualSHA256))
		if actual == "" {
			return fmt.Errorf("selected artifact sha256 is unavailable")
		}
		if actual != expectedSHA256 {
			return fmt.Errorf("selected artifact sha256 mismatch: expected=%s got=%s", expectedSHA256, actual)
		}
	}
	return nil
}

func buildAgentApprovalPins(expectedDecisionID, expectedSHA256 string, required, verified bool) *agentApprovalPins {
	expectedDecisionID = strings.TrimSpace(expectedDecisionID)
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	if !required && expectedDecisionID == "" && expectedSHA256 == "" {
		return nil
	}
	return &agentApprovalPins{
		Required:           required,
		ExpectedDecisionID: expectedDecisionID,
		ExpectedSHA256:     expectedSHA256,
		Verified:           verified,
	}
}

func validateAgentManifestIntent(manifestPath string, requireManifest bool) error {
	_, err := buildAgentManifestIntent(manifestPath, requireManifest)
	return err
}

func buildAgentManifestIntent(manifestPath string, requireManifest bool) (agentManifestIntent, error) {
	manifestPath = strings.TrimSpace(manifestPath)
	out := agentManifestIntent{
		Required: requireManifest,
		Path:     filepath.Clean(manifestPath),
	}
	if manifestPath == "" {
		out.Path = ""
	}
	if manifestPath == "" {
		if requireManifest {
			return out, fmt.Errorf("--manifest is required when --require-manifest=true")
		}
		return out, nil
	}
	loaded, err := loadAgentManifestIntent(manifestPath)
	if err != nil {
		return out, fmt.Errorf("load manifest intent: %w", err)
	}
	out.ProgramCount = len(loaded.Programs)
	out.Valid = true
	return out, nil
}

func loadAgentManifestIntent(manifestPath string) (manifest.Manifest, error) {
	loaded, err := manifest.Load(filepath.Clean(manifestPath))
	if err != nil {
		return manifest.Manifest{}, err
	}
	if len(loaded.Programs) == 0 {
		return manifest.Manifest{}, fmt.Errorf("manifest must declare at least one program")
	}
	return loaded, nil
}

func isAgentSHA256Hex(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	for _, r := range raw {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

func persistAgentApplyAuditAndLedger(workDir string, payload *agentApplyResultFile, trace runtime.DecisionTrace, operation, status, errText string) {
	audit, auditErr := runtime.PersistDecisionTrace(workDir, trace)
	if auditErr != nil {
		payload.AuditError = auditErr.Error()
	} else {
		payload.Audit = &audit
	}

	entry, err := buildAgentLoadLedgerEntry(workDir, *payload, operation, status, errText)
	if err != nil {
		payload.LoadLedgerError = err.Error()
		return
	}
	if payload.Audit != nil {
		entry.AuditTracePath = payload.Audit.TracePath
	}
	ledgerPath, err := agent.AppendLoadLedgerEntry(workDir, entry)
	if err != nil {
		payload.LoadLedgerError = err.Error()
		return
	}
	payload.LoadLedger = &entry
	payload.LoadLedgerPath = ledgerPath
}

func buildAgentLoadLedgerEntry(workDir string, payload agentApplyResultFile, operation, status, errText string) (agent.LoadLedgerEntry, error) {
	entry, err := agent.NewLoadLedgerEntry()
	if err != nil {
		return agent.LoadLedgerEntry{}, err
	}
	decision := payload.Decision
	entry.Operation = strings.TrimSpace(operation)
	if entry.Operation == "" {
		entry.Operation = "load"
	}
	entry.Status = strings.TrimSpace(status)
	if entry.Status == "" {
		entry.Status = "unknown"
	}
	entry.AgentID = decision.AgentID
	entry.Tenant = decision.Tenant
	entry.Project = decision.Project
	entry.ArtifactName = firstNonEmpty(decision.SelectedArtifact.Name, decision.ArtifactName, payload.Fetch.ArtifactName)
	entry.SelectedVersion = firstNonEmpty(decision.SelectedArtifact.Version, payload.Fetch.ArtifactVersion)
	entry.SelectedSHA256 = firstNonEmpty(decision.SelectedArtifact.SHA256, payload.Fetch.ExpectedSHA256, payload.Fetch.ActualSHA256)
	entry.ArtifactPath = payload.Fetch.OutputPath
	entry.DecisionID = decision.DecisionID
	entry.TargetProfile = decision.TargetProfile
	entry.HostProfileHint = decision.HostProfileHint
	entry.LoadApproved = decision.LoadApproved
	entry.Error = strings.TrimSpace(errText)
	if payload.ApprovalPins != nil {
		entry.ApprovalPinsRequired = payload.ApprovalPins.Required
		entry.ApprovalPinsVerified = payload.ApprovalPins.Verified
		entry.ApprovalExpectedDecisionID = payload.ApprovalPins.ExpectedDecisionID
		entry.ApprovalExpectedSHA256 = payload.ApprovalPins.ExpectedSHA256
	}
	if payload.ManifestIntent != nil {
		entry.ManifestIntentRequired = payload.ManifestIntent.Required
		entry.ManifestIntentVerified = payload.ManifestIntent.Valid
		entry.ManifestPath = payload.ManifestIntent.Path
		entry.ManifestProgramCount = payload.ManifestIntent.ProgramCount
	}
	if payload.LoadPolicy != nil {
		entry.PolicyRule = payload.LoadPolicy.RuleName
		entry.PolicyAction = payload.LoadPolicy.Action
		entry.PolicyReason = payload.LoadPolicy.Reason
	}
	if payload.Execution != nil {
		entry.ExecutionRunDir = payload.Execution.RunDir
	}
	if previous, ok, err := agent.LastSuccessfulLoad(workDir, entry.ArtifactName); err != nil {
		return agent.LoadLedgerEntry{}, err
	} else if ok {
		entry.PreviousLoadedVersion = previous.SelectedVersion
		entry.PreviousLoadedSHA256 = previous.SelectedSHA256
		entry.PreviousLoadedArtifactPath = previous.ArtifactPath
		entry.RollbackHint = fmt.Sprintf("previous successful load was %s@%s (%s)", previous.ArtifactName, previous.SelectedVersion, previous.SelectedSHA256)
	}
	return entry, nil
}

func buildAgentRollbackApplyArgs(apiURL, tenant, project, agentID, artifactName, version, targetProfile, registryToken, identityToken, workDir, outDir, outPath, loadPolicyPath, manifestPath string) []string {
	args := []string{"bpfcompat", "agent", "apply"}
	add := func(name, value string) {
		if strings.TrimSpace(value) != "" {
			args = append(args, name, value)
		}
	}
	add("--api-url", apiURL)
	add("--tenant", tenant)
	add("--project", project)
	add("--agent-id", agentID)
	add("--artifact-name", artifactName)
	add("--version", version)
	add("--target-profile", targetProfile)
	add("--workdir", workDir)
	add("--out-dir", outDir)
	add("--out", outPath)
	add("--load-policy", loadPolicyPath)
	add("--manifest", manifestPath)
	args = append(args, "--approve-load")
	if strings.TrimSpace(registryToken) != "" {
		args = append(args, "--registry-token", "[redacted]")
	}
	if strings.TrimSpace(identityToken) != "" {
		args = append(args, "--identity-token", "[redacted]")
	}
	return args
}

func rollbackExecuteArgs(displayArgs []string, registryToken, identityToken string) []string {
	if len(displayArgs) < 3 {
		return nil
	}
	args := append([]string(nil), displayArgs[3:]...)
	replaceRedacted := func(flag, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		for i := 0; i < len(args)-1; i++ {
			if args[i] == flag && args[i+1] == "[redacted]" {
				args[i+1] = value
				return
			}
		}
		args = append(args, flag, value)
	}
	replaceRedacted("--registry-token", registryToken)
	replaceRedacted("--identity-token", identityToken)
	return args
}

func recordAgentRollbackDrill(workDir string, plan agentRollbackPlan) (agent.LoadLedgerEntry, string, error) {
	entry, err := agent.NewLoadLedgerEntry()
	if err != nil {
		return agent.LoadLedgerEntry{}, "", err
	}
	entry.Operation = "rollback_drill"
	entry.Status = plan.Status
	entry.ArtifactName = plan.ArtifactName
	entry.SelectedVersion = plan.Current.SelectedVersion
	entry.SelectedSHA256 = plan.Current.SelectedSHA256
	entry.AgentID = plan.Current.AgentID
	entry.Tenant = plan.Current.Tenant
	entry.Project = plan.Current.Project
	entry.DecisionID = plan.Current.DecisionID
	entry.TargetProfile = plan.Current.TargetProfile
	entry.HostProfileHint = plan.Current.HostProfileHint
	entry.ArtifactPath = plan.Current.ArtifactPath
	entry.PreviousLoadedVersion = plan.Current.PreviousLoadedVersion
	entry.PreviousLoadedSHA256 = plan.Current.PreviousLoadedSHA256
	entry.PreviousLoadedArtifactPath = plan.Current.PreviousLoadedArtifactPath
	entry.RollbackHint = plan.Current.RollbackHint
	if plan.Status != "ready" {
		entry.Error = plan.Reason
	}
	entry.Notes = append(entry.Notes, "rollback drill recorded; use agent rollback --execute to load previous version")
	path, err := agent.AppendLoadLedgerEntry(workDir, entry)
	return entry, path, err
}

func printAgentRollbackPlan(plan agentRollbackPlan) {
	fmt.Printf("Agent rollback: %s artifact=%s current=%s\n", plan.Status, plan.ArtifactName, plan.Current.SelectedVersion)
	if plan.Previous != nil {
		fmt.Printf("Previous: %s digest=%s\n", plan.Previous.SelectedVersion, plan.Previous.SelectedSHA256)
	}
	if len(plan.RollbackCommand) > 0 {
		fmt.Printf("Command: %s\n", strings.Join(plan.RollbackCommand, " "))
	}
	if plan.Reason != "" {
		fmt.Printf("Reason: %s\n", plan.Reason)
	}
}

func resolveAgentUnloadPinPath(raw string, allowNonBPFFS bool) (string, error) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", fmt.Errorf("--pin-path is required")
	}
	abs, err := filepath.Abs(filepath.Clean(clean))
	if err != nil {
		return "", fmt.Errorf("resolve pin path: %w", err)
	}
	if abs == "/sys/fs/bpf" {
		return "", fmt.Errorf("refusing to unload bpffs root")
	}
	if !allowNonBPFFS && !strings.HasPrefix(abs, "/sys/fs/bpf/") {
		return "", fmt.Errorf("pin path must be under /sys/fs/bpf; use --allow-non-bpffs only for tests/labs")
	}
	return abs, nil
}

func removeAgentPinPath(path string, recursive bool) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.IsDir() {
		if !recursive {
			return false, fmt.Errorf("pin path is a directory; pass --recursive to remove it")
		}
		if err := os.RemoveAll(path); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	return true, nil
}

func recordAgentUnloadDrill(workDir string, plan agentUnloadPlan) (agent.LoadLedgerEntry, string, error) {
	entry, err := agent.NewLoadLedgerEntry()
	if err != nil {
		return agent.LoadLedgerEntry{}, "", err
	}
	entry.Operation = "unload"
	entry.Status = plan.Status
	entry.ArtifactName = plan.ArtifactName
	entry.Pins = []string{plan.PinPath}
	entry.Notes = append(entry.Notes, fmt.Sprintf("execute=%t removed=%t", plan.Executed, plan.Removed))
	if plan.Reason != "" {
		entry.Error = plan.Reason
	}
	path, err := agent.AppendLoadLedgerEntry(workDir, entry)
	return entry, path, err
}

func recordAgentRevocationDrill(workDir, artifactName string, result agentRevocationDrillResult) (agent.LoadLedgerEntry, string, error) {
	entry, err := agent.NewLoadLedgerEntry()
	if err != nil {
		return agent.LoadLedgerEntry{}, "", err
	}
	entry.Operation = "revocation_drill"
	entry.Status = result.Status
	entry.AgentID = result.AgentID
	entry.ArtifactName = artifactName
	entry.PolicyRule = result.Decision.RuleName
	entry.PolicyAction = result.Decision.Action
	entry.PolicyReason = result.Decision.Reason
	if result.Status != "pass" {
		entry.Error = "agent was not denied by local load policy"
	}
	entry.Notes = append(entry.Notes, "revocation drill proves local policy denies revoked host identity")
	path, err := agent.AppendLoadLedgerEntry(workDir, entry)
	return entry, path, err
}

func requestRemoteAgentDecision(apiURL string, req agent.DecisionRequest, registryToken, identityToken string) (agent.DecisionResult, error) {
	endpoint, err := resolveAgentEndpoint(apiURL)
	if err != nil {
		return agent.DecisionResult{}, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return agent.DecisionResult{}, fmt.Errorf("marshal agent decision request: %w", err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return agent.DecisionResult{}, fmt.Errorf("build agent decision request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if registryToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+registryToken)
	}
	if identityToken != "" {
		httpReq.Header.Set(agentIdentityHeader, identityToken)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return agent.DecisionResult{}, fmt.Errorf("request agent decision: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return agent.DecisionResult{}, fmt.Errorf("read agent decision response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return agent.DecisionResult{}, fmt.Errorf("agent decision HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var decoded struct {
		Decision agent.DecisionResult `json:"decision"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return agent.DecisionResult{}, fmt.Errorf("decode agent decision response: %w", err)
	}
	if decoded.Decision.SchemaVersion == "" {
		return agent.DecisionResult{}, fmt.Errorf("agent decision response missing decision")
	}
	return decoded.Decision, nil
}

func fetchAgentSelectedArtifact(
	record registry.ArtifactVersionRecord,
	selected agent.SelectedArtifact,
	remote bool,
	apiURL string,
	registryToken string,
	identityToken string,
	outDir string,
) (runtime.FetchResult, error) {
	if !remote {
		return runtime.FetchArtifact(record, outDir)
	}
	downloadURL := strings.TrimSpace(selected.DownloadURL)
	if downloadURL == "" {
		return runtime.FetchResult{}, fmt.Errorf("remote agent decision did not include download_url")
	}
	absoluteURL, err := absolutizeAgentURL(apiURL, downloadURL)
	if err != nil {
		return runtime.FetchResult{}, err
	}
	if err := os.MkdirAll(filepath.Clean(outDir), 0o755); err != nil {
		return runtime.FetchResult{}, fmt.Errorf("create agent output directory: %w", err)
	}
	targetPath := filepath.Join(filepath.Clean(outDir), agentArtifactFileName(selected))
	httpReq, err := http.NewRequest(http.MethodGet, absoluteURL, nil)
	if err != nil {
		return runtime.FetchResult{}, fmt.Errorf("build artifact download request: %w", err)
	}
	if registryToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+registryToken)
	}
	if identityToken != "" {
		httpReq.Header.Set(agentIdentityHeader, identityToken)
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(httpReq)
	if err != nil {
		return runtime.FetchResult{}, fmt.Errorf("download selected artifact: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return runtime.FetchResult{}, fmt.Errorf("download selected artifact HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	tmpPath := targetPath + ".partial"
	f, err := os.Create(tmpPath)
	if err != nil {
		return runtime.FetchResult{}, fmt.Errorf("create selected artifact file: %w", err)
	}
	h := sha256.New()
	limited := &io.LimitedReader{R: resp.Body, N: agentFetchMaxBytes + 1}
	written, copyErr := io.Copy(io.MultiWriter(f, h), limited)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return runtime.FetchResult{}, fmt.Errorf("write selected artifact: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return runtime.FetchResult{}, fmt.Errorf("close selected artifact: %w", closeErr)
	}
	if written > agentFetchMaxBytes {
		_ = os.Remove(tmpPath)
		return runtime.FetchResult{}, fmt.Errorf("selected artifact exceeds %d bytes", agentFetchMaxBytes)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	expected := strings.TrimSpace(selected.SHA256)
	if expected != "" && actual != expected {
		_ = os.Remove(tmpPath)
		return runtime.FetchResult{}, fmt.Errorf("selected artifact hash mismatch: expected=%s got=%s", expected, actual)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return runtime.FetchResult{}, fmt.Errorf("move selected artifact into place: %w", err)
	}
	return runtime.FetchResult{
		SchemaVersion:   "runtime_fetch.v0.1",
		ArtifactName:    selected.Name,
		ArtifactVersion: selected.Version,
		ArtifactVariant: selected.Variant,
		SourcePath:      absoluteURL,
		OutputPath:      targetPath,
		ExpectedSHA256:  expected,
		ActualSHA256:    actual,
	}, nil
}

func writeAgentJSON(outPath string, payload any) error {
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	raw = append(raw, '\n')
	if strings.TrimSpace(outPath) != "" {
		if err := os.WriteFile(filepath.Clean(outPath), raw, 0o644); err != nil {
			return fmt.Errorf("write JSON file: %w", err)
		}
		fmt.Printf("JSON: %s\n", outPath)
	}
	_, err = os.Stdout.Write(raw)
	return err
}

func writeAgentJSONFile(outPath string, payload any) error {
	if strings.TrimSpace(outPath) == "" {
		return nil
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Clean(outPath), raw, 0o600); err != nil {
		return fmt.Errorf("write JSON file: %w", err)
	}
	return nil
}

func writeAgentFailureJSON(outPath, phase string, cause error) {
	if strings.TrimSpace(outPath) == "" || cause == nil {
		return
	}
	payload := agentApplyResultFile{
		SchemaVersion: "agent_apply_error.v0.1",
		Phase:         strings.TrimSpace(phase),
		Error:         cause.Error(),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeAgentJSON(outPath, payload); err != nil {
		fmt.Fprintf(os.Stderr, "write agent failure result: %v\n", err)
	}
}

func summarizeAgentStatus(path string) (agentStatusSummary, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return agentStatusSummary{}, fmt.Errorf("status path is required")
	}
	cleanPath = filepath.Clean(cleanPath)
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return agentStatusSummary{}, fmt.Errorf("read %s: %w", cleanPath, err)
	}
	var file agentApplyResultFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return agentStatusSummary{}, fmt.Errorf("decode agent result: %w", err)
	}
	if file.Decision.SchemaVersion == "" && file.Fetch.SchemaVersion == "" && file.Error == "" {
		return agentStatusSummary{}, fmt.Errorf("agent result does not look like an agent apply output")
	}

	summary := agentStatusSummary{
		SchemaVersion:      agentStatusSchemaVersion,
		SourcePath:         cleanPath,
		AgentID:            file.Decision.AgentID,
		ArtifactName:       firstNonEmpty(file.Decision.SelectedArtifact.Name, file.Decision.ArtifactName, file.Fetch.ArtifactName),
		SelectedVersion:    firstNonEmpty(file.Decision.SelectedArtifact.Version, file.Fetch.ArtifactVersion),
		SelectedSHA256:     firstNonEmpty(file.Decision.SelectedArtifact.SHA256, file.Fetch.ExpectedSHA256, file.Fetch.ActualSHA256),
		TargetProfile:      file.Decision.TargetProfile,
		DecisionID:         file.Decision.DecisionID,
		LoadApproved:       file.Decision.LoadApproved,
		AuditStatus:        "missing",
		LastError:          strings.TrimSpace(file.Error),
		LastErrorPhase:     strings.TrimSpace(file.Phase),
		RequiredPassed:     file.Decision.SelectedArtifact.RequiredPassed,
		RequiredFailed:     file.Decision.SelectedArtifact.RequiredFailed,
		SummaryStatus:      file.Decision.SelectedArtifact.SummaryStatus,
		HostProfileHint:    file.Decision.HostProfileHint,
		CandidatesReviewed: file.Decision.Selection.CandidatesReviewed,
		CandidatesAccepted: file.Decision.Selection.CandidatesAccepted,
	}
	if info, statErr := os.Stat(cleanPath); statErr == nil {
		summary.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339)
	}
	if file.Decision.HistoryVerification != nil {
		verified := file.Decision.HistoryVerification.Verified
		summary.HistoryVerified = &verified
	}
	if file.LoadPolicy != nil {
		summary.LoadPolicyRule = file.LoadPolicy.RuleName
		if file.LoadPolicy.Allowed {
			summary.LoadPolicyStatus = "allow"
		} else {
			summary.LoadPolicyStatus = "deny"
			if summary.LastError == "" {
				summary.LastError = file.LoadPolicy.Reason
				summary.LastErrorPhase = "load_policy"
			}
		}
	}
	summary.LoadLedgerPath = strings.TrimSpace(file.LoadLedgerPath)
	if file.LoadLedger != nil {
		if summary.LoadLedgerPath == "" {
			summary.LoadLedgerPath = agent.LoadLedgerPath(filepath.Dir(cleanPath))
		}
		summary.PreviousLoadedVersion = file.LoadLedger.PreviousLoadedVersion
		summary.RollbackHint = file.LoadLedger.RollbackHint
	}
	if strings.TrimSpace(file.LoadLedgerError) != "" && summary.LastError == "" {
		summary.LastError = file.LoadLedgerError
		summary.LastErrorPhase = "load_ledger"
	}
	if file.Fetch.SchemaVersion != "" {
		summary.FetchOutputPath = file.Fetch.OutputPath
		if strings.TrimSpace(file.Fetch.ActualSHA256) != "" &&
			(strings.TrimSpace(file.Fetch.ExpectedSHA256) == "" || file.Fetch.ActualSHA256 == file.Fetch.ExpectedSHA256) {
			summary.FetchStatus = "success"
		} else {
			summary.FetchStatus = "error"
			if summary.LastError == "" {
				summary.LastError = "fetched artifact hash is missing or mismatched"
				summary.LastErrorPhase = "fetch"
			}
		}
	} else if summary.LastError != "" {
		summary.FetchStatus = "error"
	} else {
		summary.FetchStatus = "missing"
	}

	switch {
	case file.Execution != nil:
		summary.LoadStatus = strings.TrimSpace(file.Execution.Status)
		if summary.LoadStatus == "" {
			summary.LoadStatus = "unknown"
		}
	case strings.TrimSpace(file.LoadSkipped) != "":
		summary.LoadStatus = "skipped"
	default:
		summary.LoadStatus = "unknown"
	}
	if file.Audit != nil {
		summary.AuditStatus = "success"
		summary.AuditTracePath = file.Audit.TracePath
	} else if strings.TrimSpace(file.AuditError) != "" {
		summary.AuditStatus = "error"
		if summary.LastError == "" {
			summary.LastError = file.AuditError
			summary.LastErrorPhase = "audit"
		}
	}

	fetchOK := summary.FetchStatus == "success"
	loadOK := summary.LoadStatus == "skipped" || summary.LoadStatus == "pass" || summary.LoadStatus == "success"
	auditOK := summary.AuditStatus == "success"
	policyOK := summary.LoadPolicyStatus == "" || summary.LoadPolicyStatus == "allow"
	ledgerOK := strings.TrimSpace(file.LoadLedgerError) == ""
	summary.Healthy = summary.LastError == "" && fetchOK && loadOK && auditOK && policyOK && ledgerOK
	return summary, nil
}

func printAgentStatus(summary agentStatusSummary) {
	state := "unhealthy"
	if summary.Healthy {
		state = "healthy"
	}
	fmt.Printf("Agent status: %s\n", state)
	if summary.UpdatedAt != "" {
		fmt.Printf("Updated: %s\n", summary.UpdatedAt)
	}
	if summary.ArtifactName != "" || summary.SelectedVersion != "" {
		fmt.Printf("Artifact: %s@%s\n", summary.ArtifactName, summary.SelectedVersion)
	}
	if summary.TargetProfile != "" {
		fmt.Printf("Target: %s\n", summary.TargetProfile)
	}
	if summary.DecisionID != "" {
		fmt.Printf("Decision: %s\n", summary.DecisionID)
	}
	fmt.Printf("Fetch: %s\n", summary.FetchStatus)
	fmt.Printf("Load: %s", summary.LoadStatus)
	if !summary.LoadApproved && summary.LoadStatus == "skipped" {
		fmt.Print(" (approval not provided)")
	}
	fmt.Println()
	if summary.LoadPolicyStatus != "" {
		fmt.Printf("Load policy: %s", summary.LoadPolicyStatus)
		if summary.LoadPolicyRule != "" {
			fmt.Printf(" (%s)", summary.LoadPolicyRule)
		}
		fmt.Println()
	}
	fmt.Printf("Audit: %s\n", summary.AuditStatus)
	if summary.AuditTracePath != "" {
		fmt.Printf("Audit trace: %s\n", summary.AuditTracePath)
	}
	if summary.LoadLedgerPath != "" {
		fmt.Printf("Load ledger: %s\n", summary.LoadLedgerPath)
	}
	if summary.RollbackHint != "" {
		fmt.Printf("Rollback: %s\n", summary.RollbackHint)
	}
	if summary.LastError != "" {
		fmt.Printf("Last error: %s", summary.LastError)
		if summary.LastErrorPhase != "" {
			fmt.Printf(" (phase=%s)", summary.LastErrorPhase)
		}
		fmt.Println()
	}
}

func resolveAgentStatusPath(pathFlag string) string {
	if strings.TrimSpace(pathFlag) != "" && strings.TrimSpace(pathFlag) != defaultAgentLastResultPath {
		return pathFlag
	}
	if envPath := strings.TrimSpace(os.Getenv(agentLastResultPathEnv)); envPath != "" {
		return envPath
	}
	return pathFlag
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func resolveAgentID(raw string) string {
	if id := strings.TrimSpace(raw); id != "" {
		return id
	}
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return "local-agent"
	}
	return strings.TrimSpace(hostname)
}

func resolveAgentEndpoint(apiURL string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil {
		return "", fmt.Errorf("parse api-url: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("api-url must include scheme and host")
	}
	return base.ResolveReference(&url.URL{Path: "/api/v1/agent/decision"}).String(), nil
}

func absolutizeAgentURL(apiURL, ref string) (string, error) {
	parsedRef, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", fmt.Errorf("parse selected download_url: %w", err)
	}
	if parsedRef.IsAbs() {
		return parsedRef.String(), nil
	}
	base, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil {
		return "", fmt.Errorf("parse api-url: %w", err)
	}
	return base.ResolveReference(parsedRef).String(), nil
}

func agentRegistryToken(raw string) string {
	if token := strings.TrimSpace(raw); token != "" {
		return token
	}
	return strings.TrimSpace(os.Getenv(agentRegistryTokenEnv))
}

func agentIdentityToken(raw string) string {
	if token := strings.TrimSpace(raw); token != "" {
		return token
	}
	return strings.TrimSpace(os.Getenv(agentIdentityTokenEnv))
}

func boolEnvDefault(name string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func recordFromSelectedArtifact(selected agent.SelectedArtifact) registry.ArtifactVersionRecord {
	artifactURI := strings.TrimSpace(selected.ArtifactURI)
	return registry.ArtifactVersionRecord{
		RunID:             strings.TrimSpace(selected.RunID),
		ArtifactName:      strings.TrimSpace(selected.Name),
		ArtifactVersion:   strings.TrimSpace(selected.Version),
		ArtifactVariant:   strings.TrimSpace(selected.Variant),
		ArtifactURI:       artifactURI,
		ArtifactSHA256:    strings.TrimSpace(selected.SHA256),
		ManifestPath:      strings.TrimSpace(selected.ManifestPath),
		SummaryStatus:     strings.TrimSpace(selected.SummaryStatus),
		RequiredPassed:    selected.RequiredPassed,
		RequiredFailed:    selected.RequiredFailed,
		SupportedProfiles: append([]string(nil), selected.SupportedProfiles...),
		FailedProfiles:    append([]string(nil), selected.FailedProfiles...),
	}
}

func agentRegistryProjectWorkDir(workDir, tenant, project string) string {
	return filepath.Join(
		filepath.Clean(workDir),
		"cloud-registry",
		"tenants",
		strings.TrimSpace(tenant),
		"projects",
		strings.TrimSpace(project),
	)
}

func agentArtifactFileName(selected agent.SelectedArtifact) string {
	name := sanitizeAgentFileName(selected.Name)
	version := sanitizeAgentFileName(selected.Version)
	variant := sanitizeAgentFileName(selected.Variant)
	if name == "" {
		name = "artifact"
	}
	if version == "" {
		version = "selected"
	}
	base := name + "-" + version
	if variant != "" {
		base += "-" + variant
	}
	return base + ".bpf.o"
}

func sanitizeAgentFileName(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), ".-_")
}

func printAgentUsage() {
	fmt.Println("Usage:")
	fmt.Println("  bpfcompat agent preflight [--workdir DIR --out-dir DIR] [--include-load]")
	fmt.Println("  bpfcompat agent plan  --artifact-name <name> [--api-url URL --tenant T --project P] [flags]")
	fmt.Println("  bpfcompat agent apply --artifact-name <name> [--api-url URL --tenant T --project P] [--approve-load] [flags]")
	fmt.Println("  bpfcompat agent status [--path /var/lib/bpfcompat-agent/last-apply.json] [--json]")
	fmt.Println("  bpfcompat agent ledger [--workdir .bpfcompat] [--artifact-name name] [--json]")
	fmt.Println("  bpfcompat agent rollback --artifact-name <name> [--execute --load-policy path] [flags]")
	fmt.Println("  bpfcompat agent unload --pin-path /sys/fs/bpf/<pin> [--execute] [flags]")
	fmt.Println("  bpfcompat agent revocation-drill --agent-id <id> --load-policy path [flags]")
}
