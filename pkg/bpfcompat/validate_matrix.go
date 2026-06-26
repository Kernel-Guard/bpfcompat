package bpfcompat

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Config drives the full matrix engine via Validate: one or more kernel
// profiles, each booted in a disposable VM. This is the same engine the CLI and
// GitHub Action use. Consumers on a pre-load path want ValidateBeforeLoad
// instead — Validate boots VMs and is not host-local.
type Config struct {
	// Artifact is a local .bpf.o path or an OCI reference (OCI is fetched, so
	// it is not air-gap-safe).
	Artifact string
	Mode     Mode

	// Matrix is a path to a matrix YAML. If empty and Quick is set, the
	// built-in quick set (old LTS → recent) is used.
	Matrix string
	Quick  bool

	// Manifest optionally points at a manifest YAML (inner-map shapes,
	// runtime-sized map auto-sizing, program-type overrides, functional tests).
	Manifest string

	// Runner selects the execution backend: "" (=> "vm"), "vm", "virtme-ng",
	// or "firecracker". The host runner is not reachable here by design; use
	// ValidateBeforeLoad (hostload build) for host-local validation.
	Runner string

	Concurrency int
	Timeout     time.Duration

	// WorkDir is the run workspace root; empty uses the engine default.
	WorkDir string
}

// Report is the result of a matrix run: one Result per profile plus the raw,
// on-disk report document.
type Report struct {
	Summary Summary
	Results []Result
	RunDir  string
	Raw     schema.ReportV01
}

// Summary is the overall verdict across all profiles.
type Summary struct {
	Status string // "pass" | "fail" | ...
	Notes  []string
}

func (c Config) validationMode() string {
	if c.Mode == LoadAttach {
		return runner.ValidationModeLoadAttach
	}
	return runner.ValidationModeLoadOnly
}

// Validate runs the full matrix engine and returns the aggregated Report. A
// non-zero number of failed targets is reported in Report.Summary, not as a Go
// error — err is non-nil only when the run could not be executed.
func Validate(ctx context.Context, cfg Config) (Report, error) {
	rcfg := runner.Config{
		ArtifactPath:   cfg.Artifact,
		ValidationMode: cfg.validationMode(),
		MatrixPath:     cfg.Matrix,
		Quick:          cfg.Quick,
		ManifestPath:   cfg.Manifest,
		Runner:         cfg.Runner,
		Concurrency:    cfg.Concurrency,
		Timeout:        cfg.Timeout,
		WorkDir:        cfg.WorkDir,
	}
	if rcfg.Timeout == 0 {
		rcfg.Timeout = 10 * time.Minute
	}
	if rcfg.WorkDir == "" {
		dir, err := os.MkdirTemp("", "bpfcompat-run-")
		if err != nil {
			return Report{}, err
		}
		rcfg.WorkDir = dir
	}
	// The engine writes a report.json to OutPath; the same document is returned
	// in-memory as Report.Raw. Default to a temp file so callers need not pick a
	// path. Full run artifacts live under Report.RunDir.
	var tmpReport string
	if rcfg.OutPath == "" {
		f, err := os.CreateTemp("", "bpfcompat-report-*.json")
		if err != nil {
			return Report{}, err
		}
		tmpReport = f.Name()
		_ = f.Close()
		rcfg.OutPath = tmpReport
	}
	res, err := runner.ExecuteBootstrap(ctx, rcfg)
	if tmpReport != "" {
		os.Remove(tmpReport)
	}
	if err != nil {
		return Report{}, err
	}
	return reportFromSchema(res.RunDir, res.Report), nil
}

func reportFromSchema(runDir string, rep schema.ReportV01) Report {
	out := Report{
		Summary: Summary{Status: rep.Summary.Status, Notes: rep.Summary.Notes},
		RunDir:  runDir,
		Raw:     rep,
		Results: make([]Result, 0, len(rep.Targets)),
	}
	for _, t := range rep.Targets {
		out.Results = append(out.Results, resultFromTarget(t))
	}
	return out
}

func resultFromTarget(t schema.Target) Result {
	r := Result{
		Profile: t.ProfileID,
		Kernel: KernelInfo{
			BTF: t.BTF != nil && t.BTF.KernelBTFAvailable,
		},
		Classification: Classification{
			Code:       t.ClassificationCode,
			Confidence: t.ClassificationConfidence,
			Reason:     t.ClassificationReason,
		},
	}

	// Prefer the actually-booted host environment over the declared profile.
	if env := t.Host; env != nil {
		r.Kernel.Release, r.Kernel.Arch = env.Kernel, env.Arch
	} else if env := t.Profile; env != nil {
		r.Kernel.Release, r.Kernel.Arch = env.Kernel, env.Arch
	}

	if v := t.Validation; v != nil {
		r.Loadable = v.LoadStatus == "pass"
		r.Load = LoadResult{Status: v.LoadStatus, Errno: v.LoadErrorCode, LogTail: v.LoadError}
		r.Attach = AttachResult{
			Mode:      v.AttachMode,
			Status:    v.AttachStatus,
			Attempted: v.AttachAttempted,
			Passed:    v.AttachPassed,
			Failed:    v.AttachFailed,
		}
	} else {
		// No validation block (e.g. infra failure before load) — fall back to
		// the target's overall status.
		r.Loadable = t.Status == "pass"
		r.Load = LoadResult{Status: t.Status}
	}

	if raw, err := json.Marshal(t); err == nil {
		r.RawJSON = raw
	}
	return r
}
