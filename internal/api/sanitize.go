package api

import (
	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// The web validate/history endpoints are reachable by anonymous visitors on the
// public demo. The full report carries operator-only, host-internal details that
// should never leave the host over HTTP:
//   - absolute filesystem paths (report/markdown/artifact paths, run_dir)
//   - the per-target VM run directory, which also holds that run's SSH private key
//   - the per-target QEMU command line and serial-log path
//
// The compatibility evidence a viewer actually wants (load/attach/verifier/BTF/
// functional results, kernel info, classification, timings) is preserved.

// sanitizeReportForPublic returns a copy of the typed report with the
// host-internal fields cleared. The original on-disk report is untouched.
func sanitizeReportForPublic(r schema.ReportV01) schema.ReportV01 {
	r.Paths = schema.Paths{}
	r.Artifact.Path = ""
	r.Matrix.Path = ""
	if len(r.Targets) > 0 {
		targets := make([]schema.Target, len(r.Targets))
		copy(targets, r.Targets)
		for i := range targets {
			targets[i].VMRunDir = ""
			targets[i].QEMUCommand = ""
			targets[i].SerialLog = ""
		}
		r.Targets = targets
	}
	return r
}

// publicValidateResponse builds a validateResponse safe to return over HTTP:
// host paths are dropped and the embedded report is sanitized.
func publicValidateResponse(result runner.RunResult) *validateResponse {
	return &validateResponse{
		ExitCode: result.ExitCode,
		Report:   sanitizeReportForPublic(result.Report),
	}
}

// sanitizeReportMapForPublic strips the same host-internal fields from a report
// decoded from disk as a generic map (the history run-report endpoint).
func sanitizeReportMapForPublic(report map[string]any) map[string]any {
	if report == nil {
		return nil
	}
	delete(report, "paths")
	if a, ok := report["artifact"].(map[string]any); ok {
		delete(a, "path")
	}
	if m, ok := report["matrix"].(map[string]any); ok {
		delete(m, "path")
	}
	if targets, ok := report["targets"].([]any); ok {
		for _, t := range targets {
			if tm, ok := t.(map[string]any); ok {
				delete(tm, "vm_run_dir")
				delete(tm, "qemu_command")
				delete(tm, "serial_log")
			}
		}
	}
	return report
}
