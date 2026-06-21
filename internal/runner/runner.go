package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/artifact"
	"github.com/kernel-guard/bpfcompat/internal/classifier"
	"github.com/kernel-guard/bpfcompat/internal/manifest"
	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/report"
	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

type RunResult struct {
	RunDir   string
	ExitCode int
	Report   schema.ReportV01
}

var (
	loadProfileFn             = vm.LoadProfile
	executeProfileFn          = vm.ExecuteProfile
	executeVirtmeNGProfile    = vm.ExecuteVirtmeNGProfile
	executeFirecrackerProfile = vm.ExecuteFirecrackerProfile
)

func emitProgress(progress ProgressReporter, update ProgressUpdate) {
	if progress == nil {
		return
	}
	progress(update)
}

func normalizedRunner(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return RunnerVM
	}
	return value
}

func ExecuteBootstrap(ctx context.Context, cfg Config) (RunResult, error) {
	select {
	case <-ctx.Done():
		return RunResult{}, ctx.Err()
	default:
	}

	emitProgress(cfg.Progress, ProgressUpdate{
		Stage:   ProgressStagePrepareRun,
		Message: "Preparing run workspace",
	})

	runner := normalizedRunner(cfg.Runner)
	switch runner {
	case RunnerVM:
	case RunnerVirtmeNG:
	case RunnerFirecracker:
	case RunnerHost:
		return RunResult{}, fmt.Errorf("runner %q is intentionally unavailable in MVP to prevent host-kernel BPF loading", RunnerHost)
	default:
		return RunResult{}, fmt.Errorf("unsupported runner %q", cfg.Runner)
	}

	runPaths, err := PrepareRun(cfg.WorkDir, time.Now())
	if err != nil {
		return RunResult{}, fmt.Errorf("prepare run directory: %w", err)
	}

	emitProgress(cfg.Progress, ProgressUpdate{
		Stage:   ProgressStageInspectArtifact,
		Message: "Inspecting artifact",
	})

	artifactPath := cfg.ArtifactPath
	if artifact.IsOCISource(artifactPath) {
		emitProgress(cfg.Progress, ProgressUpdate{
			Stage:   ProgressStageInspectArtifact,
			Message: "Extracting eBPF object from OCI source",
		})
		ociDir, err := os.MkdirTemp("", "bpfcompat-oci-")
		if err != nil {
			return RunResult{}, fmt.Errorf("create OCI extract dir: %w", err)
		}
		defer os.RemoveAll(ociDir)
		extracted, err := artifact.ExtractEBPFFromOCI(artifactPath, ociDir)
		if err != nil {
			return RunResult{}, fmt.Errorf("load OCI gadget %q: %w", artifactPath, err)
		}
		artifactPath = extracted
	}

	meta, err := artifact.Inspect(artifactPath)
	if err != nil {
		return RunResult{}, err
	}

	emitProgress(cfg.Progress, ProgressUpdate{
		Stage:   ProgressStageStageArtifact,
		Message: "Staging artifact",
	})

	if _, err := artifact.Stage(meta.AbsolutePath, runPaths.InputDir); err != nil {
		return RunResult{}, err
	}

	var stagedManifest string
	var functionalPlanPath string
	var tuning validatorTuning
	validationMode := NormalizeValidationMode(cfg.ValidationMode)
	attachMode := "best-effort"
	matrixPathAbs, err := filepath.Abs(cfg.MatrixPath)
	if err != nil {
		return RunResult{}, fmt.Errorf("resolve matrix path: %w", err)
	}

	emitProgress(cfg.Progress, ProgressUpdate{
		Stage:   ProgressStageLoadMatrix,
		Message: "Loading validation matrix",
	})

	m, err := matrix.Load(matrixPathAbs)
	if err != nil {
		return RunResult{}, err
	}

	var notes []string
	if cfg.ManifestPath != "" {
		manifestPathAbs, err := filepath.Abs(cfg.ManifestPath)
		if err != nil {
			return RunResult{}, fmt.Errorf("resolve manifest path: %w", err)
		}
		emitProgress(cfg.Progress, ProgressUpdate{
			Stage:   ProgressStageLoadManifest,
			Message: "Loading manifest",
		})
		mf, err := manifest.Load(manifestPathAbs)
		if err != nil {
			return RunResult{}, err
		}
		if err := ensureManifestProfilesExist(mf, m); err != nil {
			return RunResult{}, err
		}
		if validationMode == ValidationModeLoadOnly {
			attachMode = "disabled"
		} else {
			attachMode = attachModeFromManifest(mf)
		}
		stagedManifest, err = artifact.Stage(manifestPathAbs, runPaths.InputDir)
		if err != nil {
			return RunResult{}, fmt.Errorf("stage manifest: %w", err)
		}
		if shouldRunFunctionalTests(validationMode, mf) {
			functionalPlanPath, err = writeFunctionalPlan(mf.FunctionalTests, runPaths.InputDir)
			if err != nil {
				return RunResult{}, err
			}
		}
		tuning = validatorTuningFromManifest(mf)
	}
	if validationMode == ValidationModeLoadOnly {
		attachMode = "disabled"
	}

	stagedArtifact := filepath.Join(runPaths.InputDir, filepath.Base(meta.AbsolutePath))
	validatorBinPath, err := filepath.Abs("validator/c-libbpf/bin/bpfcompat-validator")
	if err != nil {
		return RunResult{}, fmt.Errorf("resolve validator path: %w", err)
	}
	if _, err := os.Stat(validatorBinPath); err != nil {
		return RunResult{}, fmt.Errorf("validator binary not found at %s; run `make validator-static` first", validatorBinPath)
	}
	if runner == RunnerVM {
		dynamic, err := validatorIsDynamicallyLinked(validatorBinPath)
		if err != nil {
			return RunResult{}, fmt.Errorf("inspect validator binary: %w", err)
		}
		if dynamic {
			return RunResult{}, fmt.Errorf("validator binary at %s is dynamically linked; VM-backed runs require a static build (run `make validator-static`)", validatorBinPath)
		}
	}

	targets, targetNotes, hasInfraError, hasRequiredCompatFailure := executeTargets(
		ctx,
		cfg,
		m,
		runPaths.RunDir,
		stagedArtifact,
		stagedManifest,
		functionalPlanPath,
		tuning,
		validatorBinPath,
		attachMode,
		cfg.Progress,
	)
	notes = append(notes, validationModeNotes(validationMode)...)
	notes = append(notes, targetNotes...)

	status := "pass"
	exitCode := ExitSuccess
	if hasInfraError {
		status = "error"
		exitCode = ExitToolError
	} else if hasRequiredCompatFailure {
		status = "fail"
		exitCode = ExitCompatibilityFailure
	}

	reportObj := schema.ReportV01{
		SchemaVersion: "v0.1",
		Run: schema.RunInfo{
			ID:        runPaths.RunID,
			StartedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Artifact: schema.Artifact{
			Path:      meta.AbsolutePath,
			BaseName:  meta.BaseName,
			SHA256:    meta.SHA256,
			SizeBytes: meta.SizeBytes,
		},
		Matrix: schema.MatrixInfo{
			Path:     matrixPathAbs,
			Name:     m.Name,
			Profiles: m.ProfileIDs(),
		},
		Targets: targets,
		Summary: schema.SummaryInfo{
			Status: status,
			Notes:  notes,
		},
		Paths: schema.Paths{
			RunDir:   runPaths.RunDir,
			JSON:     absPathOrOriginal(cfg.OutPath),
			Markdown: absPathOrOriginal(cfg.MarkdownPath),
		},
	}

	emitProgress(cfg.Progress, ProgressUpdate{
		Stage:   ProgressStageWriteReport,
		Message: "Writing reports",
	})

	if err := report.WriteJSON(cfg.OutPath, reportObj); err != nil {
		return RunResult{}, err
	}
	if cfg.MarkdownPath != "" {
		if err := report.WriteMarkdown(cfg.MarkdownPath, reportObj); err != nil {
			return RunResult{}, err
		}
	}

	artifactName := resolveArtifactName(cfg.ArtifactName, reportObj.Artifact.BaseName)
	artifactVersion := resolveArtifactVersion(cfg.ArtifactVersion, reportObj.Run.ID)
	artifactVariant := strings.TrimSpace(cfg.ArtifactVariant)

	emitProgress(cfg.Progress, ProgressUpdate{
		Stage:   ProgressStagePersistRegistry,
		Message: "Persisting artifact history",
	})

	if err := registry.Persist(cfg.WorkDir, runPaths.RunDir, registry.RunRecord{
		RunID:           reportObj.Run.ID,
		StartedAt:       reportObj.Run.StartedAt,
		ArtifactName:    artifactName,
		ArtifactVersion: artifactVersion,
		ArtifactVariant: artifactVariant,
		ArtifactPath:    reportObj.Artifact.Path,
		ArtifactURI:     strings.TrimSpace(cfg.ArtifactURI),
		ArtifactSHA256:  reportObj.Artifact.SHA256,
		MatrixPath:      reportObj.Matrix.Path,
		MatrixName:      reportObj.Matrix.Name,
		SummaryStatus:   reportObj.Summary.Status,
		JSONReportPath:  reportObj.Paths.JSON,
		MarkdownPath:    reportObj.Paths.Markdown,
	}); err != nil {
		return RunResult{}, fmt.Errorf("persist local registry metadata: %w", err)
	}

	supportedProfiles, failedProfiles, requiredPassed, requiredFailed, classificationCodes := summarizeTargets(targets)
	if err := registry.PersistArtifactVersion(cfg.WorkDir, registry.ArtifactVersionRecord{
		RunID:              reportObj.Run.ID,
		RunStartedAt:       reportObj.Run.StartedAt,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		ArtifactName:       artifactName,
		ArtifactVersion:    artifactVersion,
		ArtifactVariant:    artifactVariant,
		ArtifactPath:       reportObj.Artifact.Path,
		ArtifactURI:        strings.TrimSpace(cfg.ArtifactURI),
		ArtifactSHA256:     reportObj.Artifact.SHA256,
		ManifestPath:       absPathOrOriginal(cfg.ManifestPath),
		MatrixPath:         reportObj.Matrix.Path,
		MatrixName:         reportObj.Matrix.Name,
		SummaryStatus:      reportObj.Summary.Status,
		RequiredPassed:     requiredPassed,
		RequiredFailed:     requiredFailed,
		TotalProfiles:      len(reportObj.Targets),
		SupportedProfiles:  supportedProfiles,
		FailedProfiles:     failedProfiles,
		ClassificationCode: classificationCodes,
		JSONReportPath:     reportObj.Paths.JSON,
		MarkdownPath:       reportObj.Paths.Markdown,
	}); err != nil {
		return RunResult{}, fmt.Errorf("persist artifact version history: %w", err)
	}

	emitProgress(cfg.Progress, ProgressUpdate{
		Stage:   ProgressStageCompleted,
		Message: "Validation completed",
	})

	return RunResult{
		RunDir:   runPaths.RunDir,
		ExitCode: exitCode,
		Report:   reportObj,
	}, nil
}

func executeTargets(
	ctx context.Context,
	cfg Config,
	m matrix.Matrix,
	runDir string,
	stagedArtifact string,
	stagedManifest string,
	functionalPlanPath string,
	tuning validatorTuning,
	validatorBinPath string,
	attachMode string,
	progress ProgressReporter,
) ([]schema.Target, []string, bool, bool) {
	targets := make([]schema.Target, len(m.Profiles))
	notes := make([]string, 0)
	hasInfraError := false
	hasRequiredCompatFailure := false

	limit := cfg.Concurrency
	if limit < 1 {
		limit = 1
	}

	type targetExecutionResult struct {
		index                   int
		target                  schema.Target
		hasInfraError           bool
		hasRequiredCompatFailed bool
	}

	sem := make(chan struct{}, limit)
	results := make(chan targetExecutionResult, len(m.Profiles))
	var wg sync.WaitGroup
	totalProfiles := len(m.Profiles)

	emitProgress(progress, ProgressUpdate{
		Stage:             ProgressStageValidateTargets,
		Message:           "Starting VM profile validation",
		TotalProfiles:     totalProfiles,
		CompletedProfiles: 0,
	})

	for i, matrixProfile := range m.Profiles {
		i := i
		matrixProfile := matrixProfile
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			emitProgress(progress, ProgressUpdate{
				Stage:         ProgressStageValidateTargets,
				Message:       fmt.Sprintf("Running profile %s", matrixProfile.ID),
				TotalProfiles: totalProfiles,
				ProfileID:     matrixProfile.ID,
				ProfileStatus: "running",
			})

			target, infraErr, requiredFail := executeTarget(
				ctx,
				cfg,
				matrixProfile,
				runDir,
				stagedArtifact,
				stagedManifest,
				functionalPlanPath,
				tuning,
				validatorBinPath,
				attachMode,
			)
			results <- targetExecutionResult{
				index:                   i,
				target:                  target,
				hasInfraError:           infraErr,
				hasRequiredCompatFailed: requiredFail,
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	completedProfiles := 0
	for result := range results {
		completedProfiles++
		targets[result.index] = result.target
		if result.hasInfraError {
			hasInfraError = true
		}
		if result.hasRequiredCompatFailed {
			hasRequiredCompatFailure = true
		}
		emitProgress(progress, ProgressUpdate{
			Stage:             ProgressStageValidateTargets,
			Message:           fmt.Sprintf("Completed profile %s (%d/%d)", result.target.ProfileID, completedProfiles, totalProfiles),
			TotalProfiles:     totalProfiles,
			CompletedProfiles: completedProfiles,
			ProfileID:         result.target.ProfileID,
			ProfileStatus:     result.target.Status,
		})
	}

	if hasInfraError {
		notes = append(notes, "At least one VM target failed with infrastructure error. Check target infra_error and serial logs.")
	} else if hasRequiredCompatFailure {
		notes = append(notes, "Compatibility check failed on at least one required profile.")
	} else {
		notes = append(notes, "All required profiles passed validator load checks.")
	}

	return targets, notes, hasInfraError, hasRequiredCompatFailure
}

func executeTarget(
	ctx context.Context,
	cfg Config,
	matrixProfile matrix.MatrixProfile,
	runDir string,
	stagedArtifact string,
	stagedManifest string,
	functionalPlanPath string,
	tuning validatorTuning,
	validatorBinPath string,
	attachMode string,
) (schema.Target, bool, bool) {
	target := schema.Target{
		ProfileID: matrixProfile.ID,
		Required:  matrixProfile.RequiredBool(),
	}

	profilePath := filepath.Join("vm", "profiles", matrixProfile.ID+".yaml")
	profilePathAbs, err := filepath.Abs(profilePath)
	if err != nil {
		target.Status = "infra_error"
		target.InfraError = fmt.Sprintf("resolve profile path: %v", err)
		return target, true, false
	}

	profile, err := loadProfileFn(profilePathAbs)
	if err != nil {
		target.Status = "infra_error"
		target.FailedStage = "infra"
		target.InfraError = fmt.Sprintf("load profile: %v", err)
		return target, true, false
	}
	target.Profile = &schema.TargetEnv{
		Distro:       profile.Distro,
		Version:      profile.Version,
		KernelFamily: profile.KernelFamily,
		Arch:         profile.Arch,
	}
	runnerName := normalizedRunner(cfg.Runner)
	executor := executeProfileFn
	if runnerName == RunnerVirtmeNG {
		if !strings.EqualFold(strings.TrimSpace(profile.Runner), RunnerVirtmeNG) {
			target.Status = "fail"
			target.FailedStage = "transport"
			target.ClassificationCode = "UNSUPPORTED_TRANSPORT"
			target.ClassificationConfidence = "high"
			target.ClassificationReason = "Profile is a QEMU/cloud-image target; use --runner vm for this profile or select an upstream-kernel virtme-ng matrix."
			target.Notes = append(target.Notes, "execution transport: virtme-ng")
			return target, false, matrixProfile.RequiredBool()
		}
		executor = executeVirtmeNGProfile
	} else if runnerName == RunnerFirecracker {
		if !strings.EqualFold(strings.TrimSpace(profile.Runner), RunnerFirecracker) {
			target.Status = "fail"
			target.FailedStage = "transport"
			target.ClassificationCode = "UNSUPPORTED_TRANSPORT"
			target.ClassificationConfidence = "high"
			target.ClassificationReason = "Profile is a QEMU/cloud-image target; use --runner vm for this profile or select a Firecracker profile."
			target.Notes = append(target.Notes, "execution transport: firecracker")
			return target, false, matrixProfile.RequiredBool()
		}
		executor = executeFirecrackerProfile
	} else if transport, supported, reason := vm.ExecutionTransport(profile); !supported {
		target.Status = "fail"
		target.FailedStage = "transport"
		target.ClassificationCode = "UNSUPPORTED_TRANSPORT"
		target.ClassificationConfidence = "high"
		target.ClassificationReason = strings.TrimSpace(reason)
		target.Notes = append(target.Notes, fmt.Sprintf("execution transport: %s", transport))
		if reason != "" {
			target.Notes = append(target.Notes, "remediation: route this profile to a supported executor path (or mark as optional until that executor is implemented).")
		}
		return target, false, matrixProfile.RequiredBool()
	}

	targetCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	execResult := executor(targetCtx, vm.ExecutionRequest{
		Profile:            profile,
		RunDir:             runDir,
		ArtifactPath:       stagedArtifact,
		ManifestPath:       stagedManifest,
		FunctionalPlanPath: functionalPlanPath,
		MapFixups:          tuning.mapFixups,
		ProgVariants:       tuning.progVariants,
		ProbeCompanions:    tuning.probeCompanions,
		ValidatorBinary:    validatorBinPath,
		AttachMode:         attachMode,
		Timeout:            cfg.Timeout,
		KeepVMOnFailure:    cfg.KeepVMOnFailure,
	})
	cancel()

	target.Status = execResult.Status
	target.StartedAt = execResult.StartedAt.Format(time.RFC3339)
	target.FinishedAt = execResult.FinishedAt.Format(time.RFC3339)
	target.DurationMs = execResult.FinishedAt.Sub(execResult.StartedAt).Milliseconds()
	target.VMRunDir = execResult.VMRunDir
	target.QEMUCommand = execResult.QEMUCommand
	target.SerialLog = execResult.SerialLogPath
	target.ValidatorResult = execResult.ValidatorResultPath
	target.ValidatorExit = execResult.ValidatorExitCode
	target.InfraError = execResult.InfraError
	target.Notes = execResult.Notes

	if execResult.Status == "infra_error" {
		target.FailedStage = "infra"
		return target, true, false
	}

	if execResult.ValidatorResultPath == "" {
		target.Status = "infra_error"
		target.FailedStage = "infra"
		target.InfraError = "validator result path is empty"
		return target, true, false
	}

	vr, err := readValidatorResult(execResult.ValidatorResultPath)
	if err != nil {
		target.Status = "infra_error"
		target.FailedStage = "infra"
		target.InfraError = fmt.Sprintf("read validator result: %v", err)
		return target, true, false
	}
	target.Notes = append(target.Notes, capabilityProbeNotes(vr)...)
	target.Notes = append(target.Notes, mapTypeHintNotes(vr.Logs.Libbpf)...)
	target.Notes = append(target.Notes, mapFixupNotes(vr)...)
	target.Notes = append(target.Notes, progVariantNotes(vr)...)
	target.Notes = append(target.Notes, perProgramLoadNotes(vr)...)
	target.BTF = &schema.TargetBTF{
		KernelBTFAvailable: vr.BTF.KernelBTFAvailable,
		ArtifactHasBTF:     vr.BTF.ArtifactHasBTF,
		ArtifactHasBTFExt:  vr.BTF.ArtifactHasBTFExt,
	}
	target.Host = &schema.TargetEnv{
		Distro:       profile.Distro,
		Version:      profile.Version,
		KernelFamily: profile.KernelFamily,
		Kernel:       vr.Host.Release,
		Arch:         vr.Host.Machine,
	}
	target.Validation = &schema.Validation{
		LoadStatus:      vr.Load.Status,
		LoadErrorCode:   vr.Load.ErrorCode,
		LoadError:       vr.Load.Error,
		AttachMode:      vr.Attach.Mode,
		AttachStatus:    vr.Attach.Status,
		AttachAttempted: vr.Attach.Attempted,
		AttachPassed:    vr.Attach.Passed,
		AttachFailed:    vr.Attach.Failed,
	}
	target.Functional = functionalFromValidator(vr)
	target.Notes = append(target.Notes, functionalNotes(vr)...)

	switch {
	case vr.Load.Status == "pass" && vr.Status == "pass":
		target.Status = "pass"
		target.FailedStage = ""
		if vr.Attach.Attempted > 0 {
			target.Notes = append(target.Notes, fmt.Sprintf(
				"attach status: %s (mode=%s attempted=%d passed=%d failed=%d)",
				vr.Attach.Status,
				vr.Attach.Mode,
				vr.Attach.Attempted,
				vr.Attach.Passed,
				vr.Attach.Failed,
			))
		}
		return target, false, false
	case vr.Load.Status == "fail":
		target.Status = "fail"
		target.FailedStage = "load"
		target.Notes = append(target.Notes, fmt.Sprintf("validator load error: code=%d message=%s", vr.Load.ErrorCode, vr.Load.Error))
		if vr.Attach.Attempted > 0 || vr.Attach.Status != "" {
			target.Notes = append(target.Notes, fmt.Sprintf(
				"attach status: %s (mode=%s attempted=%d passed=%d failed=%d)",
				vr.Attach.Status,
				vr.Attach.Mode,
				vr.Attach.Attempted,
				vr.Attach.Passed,
				vr.Attach.Failed,
			))
		}
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
			ProgramSections:    discoveredProgramSections(vr),
			TracingProbeStatus: vr.Capabilities.ProgramTypes.Tracing.Status,
			TracingProbeError:  vr.Capabilities.ProgramTypes.Tracing.ErrorCode,
		})
		target.ClassificationCode = cl.Code
		target.ClassificationConfidence = cl.Confidence
		target.ClassificationReason = cl.Reason
		target.Notes = append(target.Notes, fmt.Sprintf("classification: %s (%s)", cl.Code, cl.Confidence))
		if cl.Remediation != "" {
			target.Notes = append(target.Notes, "remediation: "+cl.Remediation)
		}
		return target, false, matrixProfile.RequiredBool()
	case vr.Status == "fail":
		target.Status = "fail"
		if vr.Functional.Status == "fail" {
			target.FailedStage = "functional"
			target.ClassificationCode = "FUNCTIONAL_TEST_FAILURE"
			target.ClassificationConfidence = "high"
			target.ClassificationReason = functionalFailureReason(vr)
			target.Notes = append(target.Notes,
				fmt.Sprintf("classification: %s (%s)", target.ClassificationCode, target.ClassificationConfidence),
				"remediation: inspect the functional test command output and ship or fix the project-specific integration test assets.",
			)
			return target, false, matrixProfile.RequiredBool()
		}
		if vr.Attach.Status == "fail" {
			target.FailedStage = "attach"
		} else {
			target.FailedStage = "validation"
		}
		target.Notes = append(target.Notes, "validator reported failure after load phase")
		if vr.Attach.Attempted > 0 || vr.Attach.Status != "" {
			target.Notes = append(target.Notes, fmt.Sprintf(
				"attach status: %s (mode=%s attempted=%d passed=%d failed=%d)",
				vr.Attach.Status,
				vr.Attach.Mode,
				vr.Attach.Attempted,
				vr.Attach.Passed,
				vr.Attach.Failed,
			))
		}
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
			ProgramSections:    discoveredProgramSections(vr),
			TracingProbeStatus: vr.Capabilities.ProgramTypes.Tracing.Status,
			TracingProbeError:  vr.Capabilities.ProgramTypes.Tracing.ErrorCode,
		})
		target.ClassificationCode = cl.Code
		target.ClassificationConfidence = cl.Confidence
		target.ClassificationReason = cl.Reason
		target.Notes = append(target.Notes, fmt.Sprintf("classification: %s (%s)", cl.Code, cl.Confidence))
		if cl.Remediation != "" {
			target.Notes = append(target.Notes, "remediation: "+cl.Remediation)
		}
		return target, false, matrixProfile.RequiredBool()
	default:
		target.Status = "infra_error"
		target.FailedStage = "infra"
		target.InfraError = fmt.Sprintf("unrecognized validator status load=%q status=%q", vr.Load.Status, vr.Status)
		return target, true, false
	}
}

func functionalFromValidator(vr validatorResult) *schema.Functional {
	if vr.Functional.Status == "" && len(vr.Functional.Tests) == 0 {
		return nil
	}
	out := &schema.Functional{
		Status: vr.Functional.Status,
		Tests:  make([]schema.FunctionalTest, 0, len(vr.Functional.Tests)),
	}
	for i := range vr.Functional.Tests {
		test := &vr.Functional.Tests[i]
		out.Tests = append(out.Tests, schema.FunctionalTest{
			Name:             test.Name,
			Required:         test.Required,
			Status:           test.Status,
			Command:          test.Command,
			TimeoutSeconds:   test.TimeoutSeconds,
			ExpectedExitCode: test.ExpectedExitCode,
			ExitCode:         test.ExitCode,
			TimedOut:         test.TimedOut,
			StdoutTail:       test.StdoutTail,
			StderrTail:       test.StderrTail,
			Error:            test.Error,
		})
	}
	return out
}

func functionalNotes(vr validatorResult) []string {
	if vr.Functional.Status == "" || vr.Functional.Status == "skipped" {
		return nil
	}
	notes := []string{fmt.Sprintf("functional status: %s", vr.Functional.Status)}
	for i := range vr.Functional.Tests {
		test := &vr.Functional.Tests[i]
		if test.Status == "pass" {
			notes = append(notes, fmt.Sprintf("functional test %q passed", test.Name))
			continue
		}
		detail := strings.TrimSpace(test.Error)
		if detail == "" {
			detail = fmt.Sprintf("exit=%d", test.ExitCode)
		}
		notes = append(notes, fmt.Sprintf("functional test %q failed: %s", test.Name, detail))
	}
	return notes
}

func functionalFailureReason(vr validatorResult) string {
	for i := range vr.Functional.Tests {
		test := &vr.Functional.Tests[i]
		if test.Required && test.Status != "pass" {
			if strings.TrimSpace(test.Error) != "" {
				return fmt.Sprintf("Required functional test %q failed: %s", test.Name, test.Error)
			}
			return fmt.Sprintf("Required functional test %q failed with exit code %d.", test.Name, test.ExitCode)
		}
	}
	return "At least one required functional test failed."
}

func capabilityProbeNotes(vr validatorResult) []string {
	var notes []string

	if !vr.Capabilities.BPFToolAvailable {
		notes = append(notes, "bpftool unavailable; used custom capability probes")
	} else if !vr.Capabilities.BPFToolProbeOK {
		notes = append(notes, "bpftool feature probe failed; used custom capability probes")
	}

	if vr.Capabilities.AttachPrereqs.Tracefs == "missing" {
		notes = append(notes, "attach prereq missing: tracefs")
	}
	if vr.Capabilities.AttachPrereqs.KprobeEvents == "missing" {
		notes = append(notes, "attach prereq missing: kprobe_events")
	}
	if vr.Capabilities.AttachPrereqs.TracepointEvents == "missing" {
		notes = append(notes, "attach prereq missing: tracepoint events")
	}

	notes = append(notes, probeNote("capability map.ringbuf", vr.Capabilities.MapTypes.Ringbuf)...)
	notes = append(notes, probeNote("capability map.perf_event_array", vr.Capabilities.MapTypes.PerfEventArray)...)
	notes = append(notes, probeNote("capability map.array", vr.Capabilities.MapTypes.Array)...)
	notes = append(notes, probeNote("capability map.hash", vr.Capabilities.MapTypes.Hash)...)
	notes = append(notes, probeNote("capability prog.tracepoint", vr.Capabilities.ProgramTypes.Tracepoint)...)
	notes = append(notes, probeNote("capability prog.kprobe", vr.Capabilities.ProgramTypes.Kprobe)...)
	notes = append(notes, probeNote("capability prog.tracing", vr.Capabilities.ProgramTypes.Tracing)...)
	notes = append(notes, probeNote("capability prog.xdp", vr.Capabilities.ProgramTypes.XDP)...)

	return notes
}

func probeNote(prefix string, probe probeStatus) []string {
	switch probe.Status {
	case "", "unknown", "supported", "inconclusive":
		return nil
	default:
		if probe.ErrorCode == 0 && probe.Error == "" {
			return []string{fmt.Sprintf("%s: %s", prefix, probe.Status)}
		}
		return []string{fmt.Sprintf("%s: %s (code=%d err=%s)", prefix, probe.Status, probe.ErrorCode, probe.Error)}
	}
}

var mapTypePattern = regexp.MustCompile(`found type = ([0-9]+)`)

func mapTypeHintNotes(libbpfLog string) []string {
	if libbpfLog == "" {
		return nil
	}
	matches := mapTypePattern.FindAllStringSubmatch(libbpfLog, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[int]struct{})
	var notes []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}

		name := mapTypeName(id)
		if name == "" {
			notes = append(notes, fmt.Sprintf("observed map type id: %d", id))
		} else {
			notes = append(notes, fmt.Sprintf("observed map type: %s (id=%d)", name, id))
		}
	}
	return notes
}

const (
	maxProgramLoadFailureNotes = 8
	maxProgramLoadLogChars     = 360
)

func perProgramLoadNotes(vr validatorResult) []string {
	notes := make([]string, 0, len(vr.Discovery.Programs)*2)
	failures := 0
	for _, program := range vr.Discovery.Programs {
		if strings.TrimSpace(program.LoadStatus) != "fail" {
			continue
		}
		failures++
		if failures > maxProgramLoadFailureNotes {
			continue
		}

		name := strings.TrimSpace(program.Name)
		if name == "" {
			name = "<unnamed>"
		}

		note := fmt.Sprintf("program load failure: name=%s", name)
		if section := strings.TrimSpace(program.Section); section != "" {
			note += fmt.Sprintf(" section=%s", section)
		}
		if program.LoadErrno != 0 {
			note += fmt.Sprintf(" errno=%d", program.LoadErrno)
		}
		notes = append(notes, note)

		if logTail := compactSingleLineTail(program.LoadLog, maxProgramLoadLogChars); logTail != "" {
			notes = append(notes, fmt.Sprintf("program load verifier tail (%s): %s", name, logTail))
		}
	}

	if failures > maxProgramLoadFailureNotes {
		notes = append(notes, fmt.Sprintf("program load failure details truncated: %d additional program(s)", failures-maxProgramLoadFailureNotes))
	}

	return notes
}

func compactSingleLineTail(text string, maxChars int) string {
	compact := strings.Join(strings.Fields(text), " ")
	if compact == "" {
		return ""
	}
	if maxChars <= 0 {
		return compact
	}
	runes := []rune(compact)
	if len(runes) <= maxChars {
		return compact
	}
	return "..." + string(runes[len(runes)-maxChars:])
}

func discoveredProgramSections(vr validatorResult) []string {
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

func mapTypeName(id int) string {
	switch id {
	case 1:
		return "hash"
	case 2:
		return "array"
	case 4:
		return "perf_event_array"
	case 27:
		return "ringbuf"
	default:
		return ""
	}
}

func progVariantNotes(vr validatorResult) []string {
	notes := make([]string, 0, len(vr.ProgramVariants))
	for _, group := range vr.ProgramVariants {
		if group.Chosen == "" {
			notes = append(notes, fmt.Sprintf(
				"program variant group %s: no variant satisfied on this kernel (disabled: %s)",
				group.Group, strings.Join(group.Disabled, ", ")))
			continue
		}
		note := fmt.Sprintf("program variant group %s: selected %s", group.Group, group.Chosen)
		if len(group.Disabled) > 0 {
			note += fmt.Sprintf(" (disabled: %s)", strings.Join(group.Disabled, ", "))
		}
		notes = append(notes, note)
	}
	return notes
}

func mapFixupNotes(vr validatorResult) []string {
	notes := make([]string, 0, len(vr.MapFixups))
	for _, fixup := range vr.MapFixups {
		switch fixup.Status {
		case "applied":
			detail := ""
			if fixup.AppliedEntries > 0 {
				detail = fmt.Sprintf(" max_entries=%d", fixup.AppliedEntries)
			}
			if fixup.InnerRingbufBytes > 0 {
				detail += fmt.Sprintf(" inner_ringbuf_bytes=%d", fixup.InnerRingbufBytes)
			}
			notes = append(notes, fmt.Sprintf("map fixup applied: %s%s", fixup.Name, detail))
		case "map_not_found":
			notes = append(notes, fmt.Sprintf("map fixup skipped: map %q not found in artifact", fixup.Name))
		case "error":
			notes = append(notes, fmt.Sprintf("map fixup failed: %s (errno=%d)", fixup.Name, fixup.Errno))
		}
	}
	return notes
}

// validatorTuning carries manifest-declared loader-contract settings (map
// fixups, program variant groups) from manifest load to VM execution.
type validatorTuning struct {
	mapFixups       []vm.MapFixup
	progVariants    []vm.ProgVariantGroup
	probeCompanions []string
}

func validatorTuningFromManifest(mf manifest.Manifest) validatorTuning {
	var tuning validatorTuning
	for _, fixup := range mf.Maps {
		tuning.mapFixups = append(tuning.mapFixups, vm.MapFixup{
			Name:              fixup.Name,
			MaxEntries:        string(fixup.MaxEntries),
			InnerRingbufBytes: fixup.InnerRingbufBytes,
		})
	}
	for _, group := range mf.ProgramVariants {
		vmGroup := vm.ProgVariantGroup{Group: group.Group}
		for _, variant := range group.Programs {
			helperID := uint32(0)
			if variant.RequiresHelper != "" {
				// Resolvability is guaranteed by manifest validation.
				helperID, _ = manifest.HelperID(variant.RequiresHelper)
			}
			vmGroup.Variants = append(vmGroup.Variants, vm.ProgVariant{
				Name:       variant.Name,
				HelperID:   helperID,
				TrialProbe: variant.Probe == "trial_load",
			})
		}
		tuning.progVariants = append(tuning.progVariants, vmGroup)
	}
	tuning.probeCompanions = append(tuning.probeCompanions, mf.ProbeCompanions...)
	return tuning
}

func attachModeFromManifest(mf manifest.Manifest) string {
	for _, program := range mf.Programs {
		if program.Attach.Required {
			return "required"
		}
	}
	return "best-effort"
}

func shouldRunFunctionalTests(validationMode string, mf manifest.Manifest) bool {
	if len(mf.FunctionalTests) == 0 {
		return false
	}
	switch validationMode {
	case ValidationModeLoadOnly, ValidationModeLoadAttach:
		return false
	case ValidationModeBehavior:
		return true
	default:
		// Preserve the pre-mode CLI/suite behavior: manifests that already
		// contained functional_tests continue to execute them unless a caller
		// explicitly selected a narrower validation mode.
		return true
	}
}

func validationModeNotes(validationMode string) []string {
	switch validationMode {
	case ValidationModeLoadOnly:
		return []string{"validation mode: load_only (libbpf load/verifier only; attach and behavior commands skipped)"}
	case ValidationModeLoadAttach:
		return []string{"validation mode: load_attach (libbpf load plus attach evidence; behavior commands skipped)"}
	case ValidationModeBehavior:
		return []string{"validation mode: behavior (load, attach, and manifest functional commands)"}
	default:
		return nil
	}
}

func ListProfiles(matrixPath string) ([]string, error) {
	m, err := matrix.Load(matrixPath)
	if err != nil {
		return nil, err
	}
	return m.ProfileIDs(), nil
}

func ensureManifestProfilesExist(mf manifest.Manifest, mx matrix.Matrix) error {
	for _, profileID := range mf.RequiredProfiles {
		if !mx.HasProfile(profileID) {
			return fmt.Errorf("manifest required profile %q is not present in matrix", profileID)
		}
	}
	return nil
}

func absPathOrOriginal(path string) string {
	if path == "" {
		return ""
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absPath
}

func resolveArtifactName(configuredName, artifactBaseName string) string {
	name := strings.TrimSpace(configuredName)
	if name != "" {
		return name
	}

	base := strings.TrimSpace(artifactBaseName)
	if strings.HasSuffix(base, ".bpf.o") {
		base = strings.TrimSuffix(base, ".bpf.o")
	}
	if strings.HasSuffix(base, ".o") {
		base = strings.TrimSuffix(base, ".o")
	}
	ext := filepath.Ext(base)
	if ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "" {
		return "artifact"
	}
	return base
}

func resolveArtifactVersion(configuredVersion, runID string) string {
	version := strings.TrimSpace(configuredVersion)
	if version != "" {
		return version
	}
	return runID
}

func summarizeTargets(targets []schema.Target) (supportedProfiles []string, failedProfiles []string, requiredPassed int, requiredFailed int, classificationCodes []string) {
	supportedProfiles = make([]string, 0, len(targets))
	failedProfiles = make([]string, 0, len(targets))
	classSeen := make(map[string]struct{})

	for _, target := range targets {
		if target.Required {
			if target.Status == "pass" {
				requiredPassed++
			} else {
				requiredFailed++
			}
		}

		if target.Status == "pass" {
			supportedProfiles = append(supportedProfiles, target.ProfileID)
		} else {
			failedProfiles = append(failedProfiles, target.ProfileID)
		}

		code := strings.TrimSpace(target.ClassificationCode)
		if code == "" {
			continue
		}
		if _, ok := classSeen[code]; ok {
			continue
		}
		classSeen[code] = struct{}{}
		classificationCodes = append(classificationCodes, code)
	}

	sort.Strings(supportedProfiles)
	sort.Strings(failedProfiles)
	sort.Strings(classificationCodes)
	return supportedProfiles, failedProfiles, requiredPassed, requiredFailed, classificationCodes
}
