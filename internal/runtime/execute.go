package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/erenari/bpfcompat/internal/classifier"
)

const executeSchemaVersion = "runtime_execute.v0.1"

type ExecuteRequest struct {
	ArtifactPath        string
	ManifestPath        string
	AttachMode          string
	ProbeFeatures       bool
	AllowHostLoad       bool
	UseSudo             bool
	SudoNonInteractive  bool
	ValidatorBinaryPath string
	WorkDir             string
	Timeout             time.Duration
}

type ExecuteResult struct {
	SchemaVersion       string                  `json:"schema_version"`
	StartedAt           string                  `json:"started_at"`
	FinishedAt          string                  `json:"finished_at"`
	DurationMs          int64                   `json:"duration_ms"`
	Status              string                  `json:"status"`
	ArtifactPath        string                  `json:"artifact_path"`
	ManifestPath        string                  `json:"manifest_path,omitempty"`
	AttachMode          string                  `json:"attach_mode"`
	ProbeFeatures       bool                    `json:"probe_features"`
	UsedSudo            bool                    `json:"used_sudo"`
	Command             []string                `json:"command"`
	ExitCode            int                     `json:"exit_code"`
	RunDir              string                  `json:"run_dir"`
	LogDir              string                  `json:"log_dir"`
	ValidatorResultPath string                  `json:"validator_result_path"`
	StderrPath          string                  `json:"stderr_path,omitempty"`
	Stderr              string                  `json:"stderr,omitempty"`
	Validator           ExecuteValidatorSummary `json:"validator"`
	Classification      *ExecuteClassification  `json:"classification,omitempty"`
	Notes               []string                `json:"notes,omitempty"`
}

type ExecuteValidatorSummary struct {
	Status             string `json:"status"`
	LoadStatus         string `json:"load_status"`
	LoadErrorCode      int    `json:"load_error_code"`
	LoadError          string `json:"load_error,omitempty"`
	AttachMode         string `json:"attach_mode"`
	AttachStatus       string `json:"attach_status"`
	AttachAttempted    int    `json:"attach_attempted"`
	AttachPassed       int    `json:"attach_passed"`
	AttachFailed       int    `json:"attach_failed"`
	KernelBTFAvailable bool   `json:"kernel_btf_available"`
	ArtifactHasBTF     bool   `json:"artifact_has_btf"`
	ArtifactHasBTFExt  bool   `json:"artifact_has_btf_ext"`
}

type ExecuteClassification struct {
	Code        string `json:"code"`
	Confidence  string `json:"confidence"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type runtimeValidatorResult struct {
	Status string `json:"status"`
	Host   struct {
		Release string `json:"release"`
	} `json:"host"`
	Load struct {
		Status    string `json:"status"`
		ErrorCode int    `json:"error_code"`
		Error     string `json:"error"`
	} `json:"load"`
	Attach struct {
		Mode      string `json:"mode"`
		Status    string `json:"status"`
		Attempted int    `json:"attempted"`
		Passed    int    `json:"passed"`
		Failed    int    `json:"failed"`
	} `json:"attach"`
	BTF struct {
		KernelBTFAvailable bool `json:"kernel_btf_available"`
		ArtifactHasBTF     bool `json:"artifact_has_btf"`
		ArtifactHasBTFExt  bool `json:"artifact_has_btf_ext"`
	} `json:"btf"`
	Capabilities struct {
		ProgramTypes struct {
			Tracing struct {
				Status    string `json:"status"`
				ErrorCode int    `json:"error_code"`
			} `json:"tracing"`
		} `json:"program_types"`
	} `json:"capabilities"`
	Discovery struct {
		Programs []struct {
			Section string `json:"section"`
		} `json:"programs"`
	} `json:"discovery"`
	Logs struct {
		Libbpf string `json:"libbpf"`
	} `json:"logs"`
}

var runHostCommandFn = func(cmd *exec.Cmd) error {
	return cmd.Run()
}

func ExecuteArtifactOnHost(ctx context.Context, req ExecuteRequest) (ExecuteResult, error) {
	if !req.AllowHostLoad {
		return ExecuteResult{}, errors.New("host execution is disabled; set allow_host_load=true to proceed")
	}

	started := time.Now().UTC()

	artifactPath, err := resolveExistingPath(req.ArtifactPath, "artifact")
	if err != nil {
		return ExecuteResult{}, err
	}
	manifestPath := strings.TrimSpace(req.ManifestPath)
	if manifestPath != "" {
		manifestPath, err = resolveExistingPath(manifestPath, "manifest")
		if err != nil {
			return ExecuteResult{}, err
		}
	}

	attachMode, err := normalizeAttachMode(req.AttachMode)
	if err != nil {
		return ExecuteResult{}, err
	}
	workDir := strings.TrimSpace(req.WorkDir)
	if workDir == "" {
		workDir = ".bpfcompat"
	}
	validatorPath, err := resolveValidatorBinary(req.ValidatorBinaryPath)
	if err != nil {
		return ExecuteResult{}, err
	}

	runID, err := randomHex(3)
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("generate runtime run id: %w", err)
	}
	runDir := filepath.Join(filepath.Clean(workDir), "runtime-runs", time.Now().UTC().Format("20060102T150405Z")+"-"+runID)
	logDir := filepath.Join(runDir, "logs")
	validatorResultPath := filepath.Join(runDir, "validator-result.json")
	stderrPath := filepath.Join(runDir, "validator.stderr")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return ExecuteResult{}, fmt.Errorf("create runtime run directories: %w", err)
	}

	probeFeatures := req.ProbeFeatures
	if !req.ProbeFeatures {
		probeFeatures = false
	}

	commandName := validatorPath
	commandArgs := []string{
		"--artifact", artifactPath,
		"--out", validatorResultPath,
		"--log-dir", logDir,
		"--attach-mode", attachMode,
		"--probe-features", boolString(probeFeatures),
	}
	if manifestPath != "" {
		commandArgs = append(commandArgs, "--manifest", manifestPath)
	}
	if req.UseSudo {
		sudoArgs := make([]string, 0, len(commandArgs)+2)
		if req.SudoNonInteractive {
			sudoArgs = append(sudoArgs, "-n")
		}
		sudoArgs = append(sudoArgs, validatorPath)
		sudoArgs = append(sudoArgs, commandArgs...)
		commandName = "sudo"
		commandArgs = sudoArgs
	}

	execCtx := ctx
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(execCtx, commandName, commandArgs...)
	var stderrBuffer bytes.Buffer
	stderrFile, err := os.Create(filepath.Clean(stderrPath))
	if err != nil {
		return ExecuteResult{}, fmt.Errorf("create validator stderr file: %w", err)
	}
	defer stderrFile.Close()
	cmd.Stderr = io.MultiWriter(&stderrBuffer, stderrFile)

	runErr := runHostCommandFn(cmd)
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return ExecuteResult{}, fmt.Errorf("execute validator command: %w", runErr)
		}
	}

	out := ExecuteResult{
		SchemaVersion:       executeSchemaVersion,
		StartedAt:           started.Format(time.RFC3339),
		FinishedAt:          time.Now().UTC().Format(time.RFC3339),
		ArtifactPath:        artifactPath,
		ManifestPath:        manifestPath,
		AttachMode:          attachMode,
		ProbeFeatures:       probeFeatures,
		UsedSudo:            req.UseSudo,
		Command:             append([]string{commandName}, commandArgs...),
		ExitCode:            exitCode,
		RunDir:              runDir,
		LogDir:              logDir,
		ValidatorResultPath: validatorResultPath,
		StderrPath:          stderrPath,
		Stderr:              strings.TrimSpace(stderrBuffer.String()),
	}
	startTime, _ := time.Parse(time.RFC3339, out.StartedAt)
	finishTime, _ := time.Parse(time.RFC3339, out.FinishedAt)
	if !startTime.IsZero() && !finishTime.IsZero() {
		out.DurationMs = finishTime.Sub(startTime).Milliseconds()
	}

	vr, readErr := readRuntimeValidatorResult(validatorResultPath)
	if readErr != nil {
		out.Status = "error"
		out.Notes = append(out.Notes, fmt.Sprintf("validator result unavailable: %v", readErr))
		if out.Stderr != "" {
			out.Notes = append(out.Notes, "validator stderr captured")
		}
		if runErr != nil {
			out.Notes = append(out.Notes, "validator command exited non-zero")
		}
		return out, nil
	}

	out.Validator = ExecuteValidatorSummary{
		Status:             strings.TrimSpace(vr.Status),
		LoadStatus:         strings.TrimSpace(vr.Load.Status),
		LoadErrorCode:      vr.Load.ErrorCode,
		LoadError:          strings.TrimSpace(vr.Load.Error),
		AttachMode:         strings.TrimSpace(vr.Attach.Mode),
		AttachStatus:       strings.TrimSpace(vr.Attach.Status),
		AttachAttempted:    vr.Attach.Attempted,
		AttachPassed:       vr.Attach.Passed,
		AttachFailed:       vr.Attach.Failed,
		KernelBTFAvailable: vr.BTF.KernelBTFAvailable,
		ArtifactHasBTF:     vr.BTF.ArtifactHasBTF,
		ArtifactHasBTFExt:  vr.BTF.ArtifactHasBTFExt,
	}

	switch {
	case out.Validator.Status == "pass" && out.Validator.LoadStatus == "pass" && exitCode == 0:
		out.Status = "pass"
	case out.Validator.Status == "fail" || out.Validator.LoadStatus == "fail" || exitCode == 2:
		out.Status = "fail"
	default:
		out.Status = "error"
	}

	if out.Status == "fail" {
		cl := classifier.Classify(classifier.Input{
			LoadStatus:         vr.Load.Status,
			LoadErrorCode:      vr.Load.ErrorCode,
			LoadError:          vr.Load.Error,
			AttachStatus:       vr.Attach.Status,
			AttachMode:         vr.Attach.Mode,
			KernelBTFAvailable: vr.BTF.KernelBTFAvailable,
			ArtifactHasBTF:     vr.BTF.ArtifactHasBTF,
			ArtifactHasBTFExt:  vr.BTF.ArtifactHasBTFExt,
			LibbpfLog:          vr.Logs.Libbpf,
			KernelRelease:      vr.Host.Release,
			ProgramSections:    runtimeDiscoveredProgramSections(vr),
			TracingProbeStatus: vr.Capabilities.ProgramTypes.Tracing.Status,
			TracingProbeError:  vr.Capabilities.ProgramTypes.Tracing.ErrorCode,
		})
		out.Classification = &ExecuteClassification{
			Code:        cl.Code,
			Confidence:  cl.Confidence,
			Reason:      cl.Reason,
			Remediation: cl.Remediation,
		}
		out.Notes = append(out.Notes, fmt.Sprintf("classification: %s (%s)", cl.Code, cl.Confidence))
	}

	if out.Status == "error" && out.Stderr != "" {
		out.Notes = append(out.Notes, "validator returned unexpected status; check stderr and result JSON")
	}

	return out, nil
}

func resolveExistingPath(pathText, label string) (string, error) {
	cleaned := strings.TrimSpace(pathText)
	if cleaned == "" {
		return "", fmt.Errorf("%s path is required", label)
	}
	absPath, err := filepath.Abs(filepath.Clean(cleaned))
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	if _, err := os.Stat(absPath); err != nil {
		return "", fmt.Errorf("%s path not found: %w", label, err)
	}
	return absPath, nil
}

// validatorBinarySearchPath captures the ordered list of places we look for
// bpfcompat-validator. Resolution stops at the first hit. The order is
// "explicit user override → packaged install → dev repo layout", so a
// production install can drop the binary in /usr/libexec without losing the
// repo-relative fallback used by `make test`.
var validatorBinarySearchPath = []string{
	"/usr/libexec/bpfcompat/bpfcompat-validator",
	"/usr/local/libexec/bpfcompat/bpfcompat-validator",
	"validator/c-libbpf/bin/bpfcompat-validator",
}

// envValidatorBinary lets operators pin an absolute path explicitly. This
// wins over the search path so air-gapped installs that ship the validator
// outside the canonical locations still work without code changes.
const envValidatorBinary = "BPFCOMPAT_VALIDATOR_BIN"

// envValidatorSHA256 is an optional integrity gate. When set, the resolved
// validator binary is hashed before the first exec and rejected on mismatch.
// Pair this with a release pipeline that publishes the expected digest so a
// tampered binary on disk is caught before it runs as root.
const envValidatorSHA256 = "BPFCOMPAT_VALIDATOR_SHA256"

func resolveValidatorBinary(pathText string) (string, error) {
	candidates := []string{}
	if v := strings.TrimSpace(pathText); v != "" {
		candidates = append(candidates, v)
	}
	if v := strings.TrimSpace(os.Getenv(envValidatorBinary)); v != "" {
		candidates = append(candidates, v)
	}
	candidates = append(candidates, validatorBinarySearchPath...)

	var lastErr error
	for _, candidate := range candidates {
		resolved, err := resolveExistingPath(candidate, "validator binary")
		if err != nil {
			lastErr = err
			continue
		}
		if err := verifyValidatorBinaryDigest(resolved); err != nil {
			return "", err
		}
		return resolved, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no validator binary found in search path")
	}
	return "", lastErr
}

// verifyValidatorBinaryDigest checks the on-disk validator binary against
// BPFCOMPAT_VALIDATOR_SHA256 if it's set. An empty env disables the check
// (preserving the dev workflow); a non-empty env that mismatches produces a
// clear error so operators know a tamper attempt was caught.
func verifyValidatorBinaryDigest(path string) error {
	expected := strings.TrimSpace(strings.ToLower(os.Getenv(envValidatorSHA256)))
	if expected == "" {
		return nil
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("open validator binary %q for digest verification: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash validator binary: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		return fmt.Errorf("validator binary digest mismatch: expected=%s got=%s path=%s", expected, got, path)
	}
	return nil
}

func normalizeAttachMode(raw string) (string, error) {
	mode := strings.TrimSpace(strings.ToLower(raw))
	if mode == "" {
		return "best-effort", nil
	}
	switch mode {
	case "best-effort", "required", "disabled":
		return mode, nil
	default:
		return "", fmt.Errorf("invalid attach mode %q (use disabled|best-effort|required)", raw)
	}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func readRuntimeValidatorResult(path string) (runtimeValidatorResult, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return runtimeValidatorResult{}, fmt.Errorf("read validator result: %w", err)
	}
	var out runtimeValidatorResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return runtimeValidatorResult{}, fmt.Errorf("parse validator result: %w", err)
	}
	return out, nil
}

func runtimeDiscoveredProgramSections(vr runtimeValidatorResult) []string {
	sections := make([]string, 0, len(vr.Discovery.Programs))
	for _, p := range vr.Discovery.Programs {
		section := strings.TrimSpace(p.Section)
		if section == "" {
			continue
		}
		sections = append(sections, section)
	}
	return sections
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
