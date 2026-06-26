package bpfcompat

import (
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// parseResult maps the validator's own result document (host-load path).
func TestParseResult_LoadPass(t *testing.T) {
	doc := []byte(`{
		"status":"pass",
		"host":{"release":"6.17.0-35-generic","machine":"x86_64"},
		"load":{"status":"pass","error_code":0,"error":""},
		"attach":{"mode":"disabled","status":"skipped"},
		"btf":{"kernel_btf_available":true,"artifact_has_btf":true},
		"capabilities":{"map_types":{"ringbuf":{"status":"supported"}},"program_types":{"kprobe":{"status":"supported"}}}
	}`)
	r, err := parseResult(doc)
	if err != nil {
		t.Fatalf("parseResult: %v", err)
	}
	if !r.OK() {
		t.Errorf("OK() = false, want true")
	}
	if r.Kernel.Release != "6.17.0-35-generic" || r.Kernel.Arch != "x86_64" || !r.Kernel.BTF {
		t.Errorf("kernel = %+v", r.Kernel)
	}
	if got := r.Capabilities.MapTypes["ringbuf"]; got != "supported" {
		t.Errorf("ringbuf cap = %q, want supported", got)
	}
	if r.Classification.Code != "" {
		t.Errorf("clean load should have no classification, got %q", r.Classification.Code)
	}
}

func TestParseResult_LoadFail_Classified(t *testing.T) {
	doc := []byte(`{
		"status":"fail",
		"host":{"release":"5.4.0-200-generic","machine":"x86_64"},
		"load":{"status":"fail","error_code":-22,"error":"Invalid argument"},
		"btf":{"kernel_btf_available":true,"artifact_has_btf":true},
		"logs":{"libbpf":"libbpf: prog 'x': failed to resolve CO-RE relocation"},
		"discovery":{"programs":[{"section":"kprobe/x"}]}
	}`)
	r, err := parseResult(doc)
	if err != nil {
		t.Fatalf("parseResult: %v", err)
	}
	if r.OK() {
		t.Errorf("OK() = true, want false")
	}
	if r.Load.Errno != -22 {
		t.Errorf("errno = %d, want -22", r.Load.Errno)
	}
	if r.Classification.Code == "" {
		t.Errorf("failed load should be classified, got empty code")
	}
}

// resultFromTarget maps the aggregated matrix schema (Validate path).
func TestResultFromTarget(t *testing.T) {
	tgt := schema.Target{
		ProfileID: "ubuntu-24.04-6.8",
		Status:    "pass",
		Host:      &schema.TargetEnv{Kernel: "6.8.0-106-generic", Arch: "x86_64"},
		BTF:       &schema.TargetBTF{KernelBTFAvailable: true},
		Validation: &schema.Validation{
			LoadStatus: "pass", AttachMode: "best-effort", AttachStatus: "pass",
			AttachAttempted: 2, AttachPassed: 2,
		},
	}
	r := resultFromTarget(tgt)
	if !r.OK() {
		t.Errorf("OK() = false, want true")
	}
	if r.Profile != "ubuntu-24.04-6.8" {
		t.Errorf("profile = %q", r.Profile)
	}
	if r.Kernel.Release != "6.8.0-106-generic" {
		t.Errorf("kernel release = %q (should prefer booted host)", r.Kernel.Release)
	}
	if r.Attach.Passed != 2 {
		t.Errorf("attach passed = %d, want 2", r.Attach.Passed)
	}
	if len(r.RawJSON) == 0 {
		t.Errorf("RawJSON should be populated")
	}
}

func TestResultFromTarget_InfraFailFallback(t *testing.T) {
	// No Validation block (infra failure before load) -> fall back to status.
	tgt := schema.Target{ProfileID: "p", Status: "fail"}
	r := resultFromTarget(tgt)
	if r.OK() {
		t.Errorf("OK() = true, want false on infra fail")
	}
	if r.Load.Status != "fail" {
		t.Errorf("load status = %q, want fail", r.Load.Status)
	}
}

func TestReportFromSchema(t *testing.T) {
	rep := schema.ReportV01{
		Summary: schema.SummaryInfo{Status: "fail", Notes: []string{"1 of 2 required targets failed"}},
		Targets: []schema.Target{
			{ProfileID: "a", Status: "pass", Validation: &schema.Validation{LoadStatus: "pass"}},
			{ProfileID: "b", Status: "fail", Validation: &schema.Validation{LoadStatus: "fail", LoadErrorCode: -22}},
		},
	}
	out := reportFromSchema("/run/dir", rep)
	if out.Summary.Status != "fail" || len(out.Summary.Notes) != 1 {
		t.Errorf("summary = %+v", out.Summary)
	}
	if len(out.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(out.Results))
	}
	if !out.Results[0].OK() || out.Results[1].OK() {
		t.Errorf("loadable mismatch: %v %v", out.Results[0].OK(), out.Results[1].OK())
	}
	if out.RunDir != "/run/dir" {
		t.Errorf("rundir = %q", out.RunDir)
	}
}
