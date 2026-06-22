package runner

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type ProgressStage string

const (
	ProgressStagePrepareRun      ProgressStage = "prepare_run"
	ProgressStageInspectArtifact ProgressStage = "inspect_artifact"
	ProgressStageStageArtifact   ProgressStage = "stage_artifact"
	ProgressStageLoadMatrix      ProgressStage = "load_matrix"
	ProgressStageLoadManifest    ProgressStage = "load_manifest"
	ProgressStageValidateTargets ProgressStage = "validate_targets"
	ProgressStageWriteReport     ProgressStage = "write_report"
	ProgressStagePersistRegistry ProgressStage = "persist_registry"
	ProgressStageCompleted       ProgressStage = "completed"
)

type ProgressUpdate struct {
	Stage             ProgressStage
	Message           string
	TotalProfiles     int
	CompletedProfiles int
	ProfileID         string
	ProfileStatus     string
}

type ProgressReporter func(ProgressUpdate)

type Config struct {
	ArtifactPath    string
	ArtifactURI     string
	ArtifactName    string
	ArtifactVersion string
	ArtifactVariant string
	ValidationMode  string
	MatrixPath      string
	// Quick selects the built-in quick-check kernel set (matrix.Quick) when no
	// MatrixPath is given — a fast local "does it load?" check.
	Quick                 bool
	ManifestPath          string
	OutPath               string
	MarkdownPath          string
	WorkDir               string
	Runner                string
	Concurrency           int
	Timeout               time.Duration
	KeepVMOnFailure       bool
	UnsafeAllowHostRunner bool
	Progress              ProgressReporter
}

const (
	RunnerVM          = "vm"
	RunnerVirtmeNG    = "virtme-ng"
	RunnerFirecracker = "firecracker"
	RunnerHost        = "host"
)

const (
	ValidationModeDefault    = ""
	ValidationModeLoadOnly   = "load_only"
	ValidationModeLoadAttach = "load_attach"
	ValidationModeBehavior   = "behavior"
)

func NormalizeValidationMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case ValidationModeLoadOnly, "load-only", "loadonly":
		return ValidationModeLoadOnly
	case ValidationModeLoadAttach, "load-attach", "loadattach":
		return ValidationModeLoadAttach
	case ValidationModeBehavior:
		return ValidationModeBehavior
	default:
		return ValidationModeDefault
	}
}

func (c Config) Validate() error {
	if c.ArtifactPath == "" {
		return errors.New("--artifact is required")
	}
	if c.MatrixPath == "" && !c.Quick {
		return errors.New("--matrix is required (or pass --quick for the default kernel set)")
	}
	if c.OutPath == "" {
		return errors.New("--out is required")
	}
	if c.Concurrency <= 0 {
		return fmt.Errorf("--concurrency must be > 0 (got %d)", c.Concurrency)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("--timeout must be > 0 (got %s)", c.Timeout)
	}
	if c.WorkDir == "" {
		return errors.New("--workdir cannot be empty")
	}
	if normalizedMode := NormalizeValidationMode(c.ValidationMode); normalizedMode == ValidationModeDefault && strings.TrimSpace(c.ValidationMode) != "" {
		return fmt.Errorf("--validation-mode must be one of %q, %q, or %q (got %q)", ValidationModeLoadOnly, ValidationModeLoadAttach, ValidationModeBehavior, c.ValidationMode)
	}

	runner := c.Runner
	if runner == "" {
		runner = RunnerVM
	}
	switch runner {
	case RunnerVM:
	case RunnerVirtmeNG:
	case RunnerFirecracker:
	case RunnerHost:
		if !c.UnsafeAllowHostRunner {
			return errors.New("--runner host is disabled by default; internal override requires --unsafe-allow-host-runner")
		}
	default:
		return fmt.Errorf("--runner must be one of %q, %q, %q, or %q (got %q)", RunnerVM, RunnerVirtmeNG, RunnerFirecracker, RunnerHost, c.Runner)
	}

	cleanOut := filepath.Clean(c.OutPath)
	if cleanOut == "." {
		return errors.New("--out must be a file path, not current directory")
	}
	if c.MarkdownPath != "" {
		cleanMD := filepath.Clean(c.MarkdownPath)
		if cleanMD == "." {
			return errors.New("--markdown must be a file path when provided")
		}
	}
	return nil
}
