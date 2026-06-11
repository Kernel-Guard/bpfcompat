package vm

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const virtmeNGRunner = "virtme-ng"

func ExecuteVirtmeNGProfile(ctx context.Context, req ExecutionRequest) (result ExecutionResult) {
	startedAt := time.Now().UTC()
	result = ExecutionResult{
		ProfileID: req.Profile.ID,
		Status:    "infra_error",
		StartedAt: startedAt,
	}
	defer func() {
		result.FinishedAt = time.Now().UTC()
	}()

	if !strings.EqualFold(strings.TrimSpace(req.Profile.Runner), virtmeNGRunner) {
		result.InfraError = fmt.Sprintf("profile %q is not a virtme-ng profile", req.Profile.ID)
		return
	}
	if _, err := exec.LookPath("vng"); err != nil {
		result.InfraError = "virtme-ng executable `vng` not found; install virtme-ng before using --runner virtme-ng"
		return
	}

	vmRunDir := filepath.Join(req.RunDir, "targets", req.Profile.ID)
	if err := os.MkdirAll(vmRunDir, 0o755); err != nil {
		result.InfraError = fmt.Sprintf("create virtme-ng run directory: %v", err)
		return
	}
	result.VMRunDir = vmRunDir

	guestRoot, err := filepath.Abs(filepath.Join(vmRunDir, "guest"))
	if err != nil {
		result.InfraError = fmt.Sprintf("resolve virtme-ng guest directory: %v", err)
		return
	}
	inputDir := filepath.Join(guestRoot, "input")
	binDir := filepath.Join(guestRoot, "bin")
	outDir := filepath.Join(guestRoot, "out")
	for _, dir := range []string{inputDir, binDir, outDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			result.InfraError = fmt.Sprintf("create virtme-ng work directory: %v", err)
			return
		}
	}

	artifactPath := filepath.Join(inputDir, "artifact.bpf.o")
	if err := copyFile(req.ArtifactPath, artifactPath, 0o644); err != nil {
		result.InfraError = fmt.Sprintf("stage artifact for virtme-ng: %v", err)
		return
	}

	validatorPath := filepath.Join(binDir, "bpfcompat-validator")
	if err := copyFile(req.ValidatorBinary, validatorPath, 0o755); err != nil {
		result.InfraError = fmt.Sprintf("stage validator for virtme-ng: %v", err)
		return
	}

	manifestArg := ""
	if req.ManifestPath != "" {
		manifestPath := filepath.Join(inputDir, "manifest.yaml")
		if err := copyFile(req.ManifestPath, manifestPath, 0o644); err != nil {
			result.InfraError = fmt.Sprintf("stage manifest for virtme-ng: %v", err)
			return
		}
		manifestArg = " --manifest " + shellQuote(manifestPath)
	}

	functionalPlanArg := ""
	if req.FunctionalPlanPath != "" {
		functionalPlanPath := filepath.Join(inputDir, "functional-plan.json")
		if err := copyFile(req.FunctionalPlanPath, functionalPlanPath, 0o644); err != nil {
			result.InfraError = fmt.Sprintf("stage functional plan for virtme-ng: %v", err)
			return
		}
		functionalPlanArg = " --functional-plan " + shellQuote(functionalPlanPath)
	}

	attachMode := strings.TrimSpace(req.AttachMode)
	if attachMode == "" {
		attachMode = "best-effort"
	}

	scriptPath := filepath.Join(guestRoot, "run-validator.sh")
	script := fmt.Sprintf(`#!/bin/sh
set +e
mkdir -p %s
%s --artifact %s%s%s%s --attach-mode %s --out %s --log-dir %s 2>%s
code=$?
echo "$code" >%s
exit 0
`,
		shellQuote(outDir),
		shellQuote(validatorPath),
		shellQuote(artifactPath),
		manifestArg,
		functionalPlanArg,
		validatorTuningArgs(req),
		shellSafeWord(attachMode),
		shellQuote(filepath.Join(outDir, "result.json")),
		shellQuote(outDir),
		shellQuote(filepath.Join(outDir, "validator.stderr")),
		shellQuote(filepath.Join(outDir, "validator-exit-code")),
	)
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		result.InfraError = fmt.Sprintf("write virtme-ng validator script: %v", err)
		return
	}
	if err := os.Chmod(scriptPath, 0o700); err != nil {
		result.InfraError = fmt.Sprintf("chmod virtme-ng validator script: %v", err)
		return
	}

	consoleLogPath := filepath.Join(vmRunDir, "virtme-ng-console.log")
	consoleLog, err := os.Create(consoleLogPath)
	if err != nil {
		result.InfraError = fmt.Sprintf("create virtme-ng console log: %v", err)
		return
	}
	defer consoleLog.Close()
	result.SerialLogPath = consoleLogPath

	args := buildVirtmeNGArgs(req.Profile, guestRoot)
	result.QEMUCommand = "vng " + strings.Join(args, " ")

	runCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "vng", args...)
	cmd.Stdout = consoleLog
	cmd.Stderr = consoleLog
	if err := cmd.Run(); err != nil {
		result.InfraError = fmt.Sprintf("run virtme-ng: %v", err)
		result.Notes = append(result.Notes, fmt.Sprintf("virtme-ng console log: %s", consoleLogPath))
		return
	}

	exitPath := filepath.Join(outDir, "validator-exit-code")
	if exitCode, err := parseExitCodeFile(exitPath); err == nil {
		result.ValidatorExitCode = exitCode
	} else {
		result.Notes = append(result.Notes, fmt.Sprintf("failed to parse validator exit code: %v", err))
	}

	localResultPath := filepath.Join(vmRunDir, "validator-result.json")
	guestResultPath := filepath.Join(outDir, "result.json")
	if err := copyFile(guestResultPath, localResultPath, 0o644); err != nil {
		if result.ValidatorExitCode != 0 {
			result.InfraError = fmt.Sprintf("validator exited with code %d and no result.json was produced", result.ValidatorExitCode)
		} else {
			result.InfraError = fmt.Sprintf("copy virtme-ng validator result: %v", err)
		}
		result.Notes = append(result.Notes, fmt.Sprintf("validator stderr path: %s", filepath.Join(outDir, "validator.stderr")))
		return
	}

	result.Status = "pass"
	result.ValidatorResultPath = localResultPath
	result.Notes = append(result.Notes,
		fmt.Sprintf("virtme-ng kernel: %s", strings.TrimSpace(req.Profile.VirtmeNG.Run)),
		"Validator executed inside virtme-ng upstream-kernel VM and result was copied back.",
	)
	return
}

func buildVirtmeNGArgs(profile Profile, guestRoot string) []string {
	memoryMB, cpus := boundedVMResources(profile.Boot)
	run := strings.TrimSpace(profile.VirtmeNG.Run)
	if run != "" && !strings.HasPrefix(run, "v") && !filepath.IsAbs(run) {
		run = "v" + run
	}

	args := []string{
		"--run", run,
		"--user", "root",
		"--memory", fmt.Sprintf("%d", memoryMB),
		"--cpus", fmt.Sprintf("%d", cpus),
		"--rwdir=" + guestRoot,
		"--exec", filepath.Join(guestRoot, "run-validator.sh"),
	}
	if arch := normalizeArch(profile.Arch); arch != "" && arch != normalizeArch(runtimeArch()) {
		args = append(args, "--arch", arch)
	}
	for _, extra := range profile.VirtmeNG.ExtraArgs {
		extra = strings.TrimSpace(extra)
		if extra != "" {
			args = append(args, extra)
		}
	}
	return args
}

func runtimeArch() string {
	return runtime.GOARCH
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func shellSafeWord(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "best-effort"
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return "best-effort"
	}
	return value
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
