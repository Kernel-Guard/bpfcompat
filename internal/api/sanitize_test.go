package api

import (
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

func sampleInternalReport() schema.ReportV01 {
	return schema.ReportV01{
		SchemaVersion: "0.1",
		Artifact:      schema.Artifact{Path: "/home/azureuser/secret/aegis.bpf.o", BaseName: "aegis", SHA256: "abc"},
		Matrix:        schema.MatrixInfo{Path: "/home/azureuser/matrices/mvp.yaml", Name: "mvp"},
		Targets: []schema.Target{{
			ProfileID:   "debian-12-6.1",
			Status:      "pass",
			VMRunDir:    ".bpfcompat/runs/20260616-abc/vm",
			QEMUCommand: "qemu-system-x86_64 -drive file=.bpfcompat/runs/20260616-abc/id_ed25519",
			SerialLog:   ".bpfcompat/runs/20260616-abc/serial.log",
			Validation:  &schema.Validation{LoadStatus: "ok"},
		}},
		Paths: schema.Paths{RunDir: ".bpfcompat/runs/20260616-abc", JSON: "/home/azureuser/reports/x.json", Markdown: "/home/azureuser/reports/x.md"},
	}
}

func TestSanitizeReportForPublicStripsInternalFields(t *testing.T) {
	got := sanitizeReportForPublic(sampleInternalReport())

	if got.Paths != (schema.Paths{}) {
		t.Errorf("expected paths cleared, got %+v", got.Paths)
	}
	if got.Artifact.Path != "" {
		t.Errorf("expected artifact path cleared, got %q", got.Artifact.Path)
	}
	if got.Matrix.Path != "" {
		t.Errorf("expected matrix path cleared, got %q", got.Matrix.Path)
	}
	tg := got.Targets[0]
	if tg.VMRunDir != "" || tg.QEMUCommand != "" || tg.SerialLog != "" {
		t.Errorf("expected target internals cleared, got vm_run_dir=%q qemu=%q serial=%q", tg.VMRunDir, tg.QEMUCommand, tg.SerialLog)
	}
	// Compatibility evidence must survive.
	if tg.Status != "pass" || tg.Validation == nil || tg.Validation.LoadStatus != "ok" {
		t.Errorf("sanitizer dropped compatibility evidence: %+v", tg)
	}
	if got.Artifact.SHA256 != "abc" || got.Artifact.BaseName != "aegis" {
		t.Errorf("sanitizer dropped artifact identity: %+v", got.Artifact)
	}
}

func TestSanitizeReportForPublicDoesNotMutateOriginal(t *testing.T) {
	orig := sampleInternalReport()
	_ = sanitizeReportForPublic(orig)
	if orig.Targets[0].SerialLog == "" || orig.Paths.JSON == "" {
		t.Fatal("sanitizer mutated the original report")
	}
}

func TestPublicValidateResponseDropsHostPaths(t *testing.T) {
	resp := publicValidateResponse(runner.RunResult{
		ExitCode: 0,
		RunDir:   ".bpfcompat/runs/20260616-abc",
		Report:   sampleInternalReport(),
	})
	if resp.RunDir != "" || resp.ReportJSONPath != "" || resp.ReportMarkdownPath != "" {
		t.Errorf("expected host paths dropped, got run_dir=%q json=%q md=%q", resp.RunDir, resp.ReportJSONPath, resp.ReportMarkdownPath)
	}
}

func TestSanitizeReportMapForPublic(t *testing.T) {
	report := map[string]any{
		"paths":    map[string]any{"json": "/home/azureuser/x.json"},
		"artifact": map[string]any{"path": "/home/azureuser/a.bpf.o", "sha256": "abc"},
		"matrix":   map[string]any{"path": "/home/azureuser/m.yaml", "name": "mvp"},
		"targets": []any{
			map[string]any{"profile_id": "debian-12-6.1", "status": "pass", "vm_run_dir": "x", "qemu_command": "y", "serial_log": "z"},
		},
	}
	got := sanitizeReportMapForPublic(report)

	if _, ok := got["paths"]; ok {
		t.Error("expected paths removed")
	}
	if a := got["artifact"].(map[string]any); a["path"] != nil || a["sha256"] != "abc" {
		t.Errorf("artifact not sanitized correctly: %+v", a)
	}
	tg := got["targets"].([]any)[0].(map[string]any)
	if tg["vm_run_dir"] != nil || tg["qemu_command"] != nil || tg["serial_log"] != nil {
		t.Errorf("target internals not removed: %+v", tg)
	}
	if tg["status"] != "pass" {
		t.Errorf("target status dropped: %+v", tg)
	}
}
