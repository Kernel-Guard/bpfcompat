package bpfcompat

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	// Concurrency is the number of profiles run in parallel; 0 means 1.
	// Timeout bounds each profile run; 0 means 10 minutes. Negative values
	// are rejected.
	Concurrency int
	Timeout     time.Duration

	// WorkDir is the run workspace root; run artifacts land under
	// <WorkDir>/runs/<id> (Report.RunDir). A caller-supplied WorkDir is never
	// removed by this package. If empty, Validate creates a private temp
	// directory (os.MkdirTemp, prefix "bpfcompat-run-"): it is removed when
	// Validate returns an error, and on success it is returned as
	// Report.TempWorkDir for the caller to remove with Report.Cleanup.
	WorkDir string
}

// Report is the result of a matrix run: one Result per profile plus the raw,
// on-disk report document.
type Report struct {
	Summary Summary
	Results []Result
	RunDir  string
	Raw     schema.ReportV01

	// TempWorkDir is the private workspace root Validate created because
	// Config.WorkDir was empty. RunDir lives inside it. It is NOT removed
	// automatically (the run artifacts under RunDir are part of the result);
	// the caller owns it and should call Cleanup once done with RunDir. Empty
	// when the caller supplied Config.WorkDir — that directory is never
	// removed by this package.
	TempWorkDir string
}

// Cleanup removes TempWorkDir, the private workspace Validate created when
// Config.WorkDir was empty, including everything under RunDir. It is a no-op
// when TempWorkDir is empty (caller-supplied WorkDir) and safe to call more
// than once.
func (r Report) Cleanup() error {
	if r.TempWorkDir == "" {
		return nil
	}
	return os.RemoveAll(r.TempWorkDir)
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

// executeBootstrapFn is the matrix engine entry point; a seam so tests can
// exercise Validate's workspace handling without booting VMs.
var executeBootstrapFn = runner.ExecuteBootstrap

// Validate runs the full matrix engine and returns the aggregated Report. A
// non-zero number of failed targets is reported in Report.Summary, not as a Go
// error — err is non-nil only when the run could not be executed. cfg is
// checked with the same rules as the CLI before anything is written to disk;
// a rejected config returns an error prefixed "bpfcompat: invalid config: ".
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
	if rcfg.Concurrency == 0 {
		rcfg.Concurrency = 1
	}
	// Apply the same checks the CLI applies, before any temp state is created.
	// WorkDir and OutPath are filled in by Validate below when empty, so check
	// with stand-ins for those two only.
	vcfg := rcfg
	if vcfg.WorkDir == "" {
		vcfg.WorkDir = os.TempDir()
	}
	vcfg.OutPath = filepath.Join(os.TempDir(), "bpfcompat-report.json")
	if err := vcfg.Validate(); err != nil {
		return Report{}, fmt.Errorf("bpfcompat: invalid config: %w", err)
	}
	// tempWorkDir is the private workspace this call creates, if any. Nothing
	// outside Validate knows its path until it is returned in the Report, so
	// every error path below must remove it.
	var tempWorkDir string
	if rcfg.WorkDir == "" {
		dir, err := os.MkdirTemp("", "bpfcompat-run-")
		if err != nil {
			return Report{}, err
		}
		tempWorkDir = dir
		rcfg.WorkDir = dir
	}
	// The engine writes a report.json to OutPath; the same document is returned
	// in-memory as Report.Raw. Default to a temp file so callers need not pick a
	// path. Full run artifacts live under Report.RunDir.
	var tmpReport string
	if rcfg.OutPath == "" {
		f, err := os.CreateTemp("", "bpfcompat-report-*.json")
		if err != nil {
			removeTempWorkDir(tempWorkDir)
			return Report{}, err
		}
		tmpReport = f.Name()
		_ = f.Close()
		rcfg.OutPath = tmpReport
	}
	res, err := executeBootstrapFn(ctx, rcfg)
	if tmpReport != "" {
		os.Remove(tmpReport)
	}
	if err != nil {
		removeTempWorkDir(tempWorkDir)
		return Report{}, err
	}
	rep := reportFromSchema(res.RunDir, res.Report)
	rep.TempWorkDir = tempWorkDir
	return rep, nil
}

// removeTempWorkDir best-effort removes a workspace Validate created itself.
// It never touches a caller-supplied WorkDir (dir is empty in that case).
func removeTempWorkDir(dir string) {
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
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
