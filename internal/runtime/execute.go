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
	"syscall"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/classifier"
)

const executeSchemaVersion = "runtime_execute.v0.1"

type ExecuteRequest struct {
	ArtifactPath string
	// ArtifactRoot is the staging directory the caller fetched the
	// artifact into (its --out-dir / server fetch dir). It is required:
	// ArtifactPath must resolve inside it and is opened relative to it.
	ArtifactRoot string
	// ExpectedSHA256 is the verified digest of the artifact (from the
	// verified registry record / fetch). It is required: the bytes the
	// validator loads are re-hashed against it immediately before exec.
	ExpectedSHA256      string
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
	ExpectedSHA256      string                  `json:"expected_sha256,omitempty"`
	ArtifactSHA256      string                  `json:"artifact_sha256,omitempty"`
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

	expectedSHA256, err := normalizeExpectedArtifactSHA256(req.ExpectedSHA256)
	if err != nil {
		return ExecuteResult{}, err
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

	// SECURITY: never hand the validator (often run as root) the staging
	// path itself. It may live in a shared, group/other-writable --out-dir
	// where another local user can swap or symlink the object after
	// FetchArtifact verified it. Copy the bytes through a no-follow fd into
	// a fresh private 0700 directory, verify the digest of exactly the
	// bytes written, and exec on that copy.
	artifactRoot, artifactRel, err := containArtifactPath(req.ArtifactRoot, artifactPath)
	if err != nil {
		return ExecuteResult{}, err
	}
	privateDir, privateArtifactPath, err := stageVerifiedExecCopy(artifactRoot, artifactRel, expectedSHA256)
	if err != nil {
		return ExecuteResult{}, err
	}
	defer func() { _ = os.RemoveAll(privateDir) }()

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
		"--artifact", privateArtifactPath,
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
		ExpectedSHA256:      expectedSHA256,
		ArtifactSHA256:      expectedSHA256,
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

// VerifiedSHA256 is the digest a fetched artifact was verified against: the
// record's expected sha256 when present (FetchArtifact enforces equality),
// otherwise the digest computed at fetch time. Host execution re-checks the
// bytes it hands the validator against this value.
func (f FetchResult) VerifiedSHA256() string {
	if expected := strings.TrimSpace(f.ExpectedSHA256); expected != "" {
		return expected
	}
	return strings.TrimSpace(f.ActualSHA256)
}

func normalizeExpectedArtifactSHA256(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return "", errors.New("expected artifact sha256 is required for host execution")
	}
	if len(v) != sha256.Size*2 {
		return "", fmt.Errorf("expected artifact sha256 %q is not a sha256 hex digest", raw)
	}
	if _, err := hex.DecodeString(v); err != nil {
		return "", fmt.Errorf("expected artifact sha256 %q is not a sha256 hex digest", raw)
	}
	return v, nil
}

// privateExecArtifactName is the fixed file name of the private copy the
// validator loads; it never derives from caller- or registry-supplied input.
const privateExecArtifactName = "artifact.bpf.o"

// containArtifactPath requires artifactPath to resolve strictly inside
// root and returns the absolute root plus the local relative path. The
// relative path comes from filepath.Rel and is checked with
// filepath.IsLocal, so it cannot contain ".." or be absolute.
func containArtifactPath(root, artifactPath string) (string, string, error) {
	if strings.TrimSpace(root) == "" {
		return "", "", errors.New("artifact root (the fetch staging directory) is required for host execution")
	}
	rootAbs, err := filepath.Abs(filepath.Clean(strings.TrimSpace(root)))
	if err != nil {
		return "", "", fmt.Errorf("resolve artifact root: %w", err)
	}
	pathAbs, err := filepath.Abs(filepath.Clean(artifactPath))
	if err != nil {
		return "", "", fmt.Errorf("resolve artifact path: %w", err)
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil || rel == "." {
		return "", "", fmt.Errorf("artifact path %s is outside the artifact root %s", pathAbs, rootAbs)
	}
	// Kept as its own statement so the IsLocal guard plainly dominates the
	// use of rel (CodeQL go/path-injection recognises filepath.IsLocal).
	if !filepath.IsLocal(rel) {
		return "", "", fmt.Errorf("artifact path %s is outside the artifact root %s", pathAbs, rootAbs)
	}
	return rootAbs, rel, nil
}

// stageVerifiedExecCopy opens rel inside root (os.Root: no component may
// escape root, and a final symlink is refused), copies it into a new
// private 0700 directory and checks the sha256 of exactly the bytes
// written against expectedSHA256. On success the caller owns the returned
// directory and must remove it; on any error it has already been removed.
func stageVerifiedExecCopy(root, rel, expectedSHA256 string) (string, string, error) {
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return "", "", fmt.Errorf("open artifact root: %w", err)
	}
	defer rootFS.Close()
	// O_NONBLOCK keeps a FIFO swapped in for the artifact from blocking the
	// open forever; it is refused by the regular-file check below and has
	// no effect on reads from a regular file.
	src, err := rootFS.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", "", fmt.Errorf("open artifact for pre-execute verification (symlinks and paths escaping the root are refused): %w", err)
	}
	defer src.Close()
	sourcePath := filepath.Join(root, rel)
	info, err := src.Stat()
	if err != nil {
		return "", "", fmt.Errorf("stat artifact for pre-execute verification: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("artifact %s is not a regular file", sourcePath)
	}

	dir, err := os.MkdirTemp("", "bpfcompat-exec-")
	if err != nil {
		return "", "", fmt.Errorf("create private execute directory: %w", err)
	}
	privatePath, err := copyAndVerifyIntoPrivateDir(src, info.Size(), dir, expectedSHA256, sourcePath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", "", err
	}
	return dir, privatePath, nil
}

func copyAndVerifyIntoPrivateDir(src *os.File, size int64, dir, expectedSHA256, sourcePath string) (string, error) {
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("restrict private execute directory: %w", err)
	}
	privatePath := filepath.Join(dir, privateExecArtifactName)
	dst, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return "", fmt.Errorf("create private artifact copy: %w", err)
	}
	h := sha256.New()
	// Bound the copy to the size seen at open; a file that grows afterwards
	// fails the digest check instead of filling the temp filesystem.
	_, copyErr := io.Copy(io.MultiWriter(dst, h), io.LimitReader(src, size+1))
	closeErr := dst.Close()
	if copyErr != nil {
		return "", fmt.Errorf("copy artifact to private execute directory: %w", copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close private artifact copy: %w", closeErr)
	}
	if actual := hex.EncodeToString(h.Sum(nil)); actual != expectedSHA256 {
		return "", fmt.Errorf("artifact sha256 mismatch before host execute: expected=%s got=%s path=%s", expectedSHA256, actual, sourcePath)
	}
	return privatePath, nil
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
