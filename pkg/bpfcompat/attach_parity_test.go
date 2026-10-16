package bpfcompat

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Attach evidence parity: the library must report the same per-program
// accounting, coverage, accounting state and verdict as the CLI for the same
// validator document. These are synthetic validator documents (no BPF load).

type prog struct {
	name, section, outcome string
	selected               bool
	errno                  int
	detail                 string
}

type doc struct {
	mode                     string // validator attach mode ("required", "best-effort", "disabled")
	accounting               bool   // false: an older validator without accounting
	loadFail                 bool
	status                   string // attach.status
	attempted, passed, fails int
	notAttachable            int
	programs                 []prog
	breakCounts              bool // contradictory accounting
}

func (d doc) bytes(t *testing.T) []byte {
	t.Helper()
	selected, notSelected := 0, 0
	programs := make([]map[string]any, 0, len(d.programs))
	for _, p := range d.programs {
		if p.selected {
			selected++
		} else {
			notSelected++
		}
		legacy := map[string]string{"attached": "pass", "failed": "fail"}[p.outcome]
		if legacy == "" {
			legacy = "skipped"
		}
		rec := map[string]any{"name": p.name, "section": p.section, "load_status": "pass", "attach_status": legacy}
		if p.outcome == "failed" {
			rec["attach_error"] = p.detail
		}
		if d.accounting {
			rec["autoload"] = p.selected
			rec["attach_outcome"] = p.outcome
			rec["attach_errno"] = p.errno
			if p.outcome == "attached" || p.outcome == "failed" {
				rec["attach_operation"] = "bpf_program__attach"
			}
		}
		programs = append(programs, rec)
	}
	attach := map[string]any{"mode": d.mode, "status": d.status, "attempted": d.attempted, "passed": d.passed, "failed": d.fails}
	if d.accounting {
		passed := d.passed
		if d.breakCounts {
			passed++ // per-program outcomes and counts now disagree
		}
		attach["passed"] = passed
		attach["attempted"] = d.attempted
		attach["accounting"] = "v1"
		attach["effective_mode"] = d.mode
		attach["program_count"] = len(d.programs)
		attach["records"] = len(d.programs)
		attach["selected"] = selected
		attach["not_selected"] = notSelected
		attach["attachable"] = selected - d.notAttachable
		attach["not_attachable"] = d.notAttachable
		if d.breakCounts {
			attach["attempted"] = d.attempted + 1
		}
	}
	status := "pass"
	load := map[string]any{"status": "pass", "error_code": 0, "error": ""}
	if d.loadFail {
		status = "fail"
		load = map[string]any{"status": "fail", "error_code": -22, "error": "Invalid argument"}
	}
	if d.status == "fail" {
		status = "fail"
	}
	b, err := json.Marshal(map[string]any{
		"schema_version": "v0.1", "status": status,
		"host":      map[string]any{"release": "6.8.0-100-generic", "machine": "x86_64"},
		"load":      load,
		"attach":    attach,
		"btf":       map[string]any{"kernel_btf_available": true, "artifact_has_btf": true},
		"discovery": map[string]any{"programs": programs},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var (
	tpAttached  = prog{name: "tp_a", section: "tracepoint/syscalls/sys_enter_getpid", outcome: "attached", selected: true}
	tpAttached2 = prog{name: "tp_b", section: "tracepoint/syscalls/sys_enter_getppid", outcome: "attached", selected: true}
	xdpUnexer   = prog{name: "xdp_pass", section: "xdp", outcome: "not_attachable_by_validator", selected: true}
	kpFailed    = prog{name: "kp_x", section: "kprobe/does_not_exist", outcome: "failed", selected: true, errno: -2, detail: "No such file or directory"}
)

func TestLibraryRequiredMixedObjectIsUnsupported(t *testing.T) {
	d := doc{mode: "required", accounting: true, status: "pass", attempted: 1, passed: 1, notAttachable: 1, programs: []prog{tpAttached, xdpUnexer}}
	r, err := parseResult(d.bytes(t), newConfig(WithMode(LoadAttachRequired)))
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK() || r.Compatible() {
		t.Fatalf("loaded but required attach not established: OK=%v Compatible=%v", r.OK(), r.Compatible())
	}
	if r.Status != "unsupported" || r.Verdict != schema.VerdictUnsupported || r.FailedStage != "attach" ||
		r.Classification.Code != "ATTACH_NOT_EXERCISED" || !strings.Contains(r.Classification.Reason, "xdp") {
		t.Fatalf("got %s/%s/%s/%s %q", r.Status, r.Verdict, r.FailedStage, r.Classification.Code, r.Classification.Reason)
	}
	a := r.Attach
	if a.Accounting != "v1" || a.Coverage != "partial" || a.EffectiveMode != "required" || a.Selected != 2 || a.NotAttachable != 1 {
		t.Fatalf("attach evidence = %+v", a)
	}
	if len(a.Programs) != 2 || a.Programs[1].Name != "xdp_pass" || a.Programs[1].Outcome != "not_attachable_by_validator" {
		t.Fatalf("per-program accounting = %+v", a.Programs)
	}
	if !noteContains(r.Notes, "attach not fully exercised") {
		t.Fatalf("notes = %q", r.Notes)
	}
}

// The same object in best-effort mode stays COMPATIBLE but must still say the
// attach scope was only partly exercised.
func TestLibraryBestEffortMixedObjectRecordsPartialCoverage(t *testing.T) {
	d := doc{mode: "best-effort", accounting: true, status: "pass", attempted: 1, passed: 1, notAttachable: 1, programs: []prog{tpAttached, xdpUnexer}}
	r, err := parseResult(d.bytes(t), newConfig(WithMode(LoadAttach)))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Compatible() || r.Classification.Code != "" || r.Attach.Coverage != "partial" || !noteContains(r.Notes, "attach not fully exercised") {
		t.Fatalf("got verdict=%s code=%s coverage=%s notes=%q", r.Verdict, r.Classification.Code, r.Attach.Coverage, r.Notes)
	}
}

func TestLibraryRequiredProvenFailureIsAttachFailed(t *testing.T) {
	d := doc{mode: "required", accounting: true, status: "fail", attempted: 2, passed: 1, fails: 1, programs: []prog{tpAttached, kpFailed}}
	r, err := parseResult(d.bytes(t), newConfig(WithMode(LoadAttachRequired)))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "fail" || r.Verdict != schema.VerdictIncompatible || r.Classification.Code != "ATTACH_FAILED" || r.FailedStage != "attach" {
		t.Fatalf("got %s/%s/%s/%s", r.Status, r.Verdict, r.Classification.Code, r.FailedStage)
	}
	p := r.Attach.Programs[1]
	if p.Name != "kp_x" || p.Outcome != "failed" || p.Errno != -2 || p.ReasonClass != "ERRNO_ENOENT" || p.Attribution != "errno_only" {
		t.Fatalf("failed program record = %+v", p)
	}
}

func TestLibraryRequiredAccountingUnavailableIsInfraError(t *testing.T) {
	d := doc{mode: "required", accounting: false, status: "pass", attempted: 1, passed: 1, programs: []prog{tpAttached}}
	r, err := parseResult(d.bytes(t), newConfig(WithMode(LoadAttachRequired)))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "infra_error" || r.Verdict != schema.VerdictInfraError || r.Classification.Code != "ATTACH_ACCOUNTING_UNAVAILABLE" {
		t.Fatalf("got %s/%s/%s", r.Status, r.Verdict, r.Classification.Code)
	}
	if r.Attach.Accounting != "unavailable" || r.Attach.Coverage != "unavailable" || len(r.Attach.Programs) != 0 {
		t.Fatalf("attach = %+v", r.Attach)
	}
}

func TestLibraryRequiredContradictoryAccountingIsDiscarded(t *testing.T) {
	d := doc{mode: "required", accounting: true, breakCounts: true, status: "pass", attempted: 2, passed: 2, programs: []prog{tpAttached, tpAttached2}}
	r, err := parseResult(d.bytes(t), newConfig(WithMode(LoadAttachRequired)))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "infra_error" || r.Classification.Code != "ATTACH_ACCOUNTING_INCONSISTENT" {
		t.Fatalf("got %s/%s", r.Status, r.Classification.Code)
	}
	if r.Attach.Accounting != "inconsistent" || len(r.Attach.Programs) != 0 || !noteContains(r.Notes, "attach accounting discarded") {
		t.Fatalf("contradictory per-program detail must not be carried: attach=%+v notes=%q", r.Attach, r.Notes)
	}
}

func TestLibraryRequiredProgramsOption(t *testing.T) {
	d := doc{mode: "required", accounting: true, status: "pass", attempted: 2, passed: 2, programs: []prog{tpAttached, tpAttached2}}
	r, err := parseResult(d.bytes(t), newConfig(WithMode(LoadAttachRequired), WithRequiredPrograms("tp_a", "tp_missing")))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "unsupported" || r.Classification.Code != "ATTACH_NOT_EXERCISED" || !strings.Contains(r.Classification.Reason, "tp_missing") {
		t.Fatalf("got %s/%s %q", r.Status, r.Classification.Code, r.Classification.Reason)
	}
	// Outside required mode the option is ignored.
	d.mode = "best-effort"
	r, err = parseResult(d.bytes(t), newConfig(WithMode(LoadAttach), WithRequiredPrograms("tp_missing")))
	if err != nil || !r.Compatible() {
		t.Fatalf("best-effort with required names: %+v, %v", r, err)
	}
}

// Parity: for each document the library result carries exactly the runner's
// evaluation (which is itself checked against the matrix runner's
// executeTarget in internal/runner/validator_evidence_test.go).
func TestLibraryMatchesRunnerEvaluation(t *testing.T) {
	cases := []struct {
		mode Mode
		d    doc
	}{
		{LoadAttachRequired, doc{mode: "required", accounting: true, status: "pass", attempted: 1, passed: 1, notAttachable: 1, programs: []prog{tpAttached, xdpUnexer}}},
		{LoadAttachRequired, doc{mode: "required", accounting: true, status: "fail", attempted: 2, passed: 1, fails: 1, programs: []prog{tpAttached, kpFailed}}},
		{LoadAttach, doc{mode: "best-effort", accounting: true, status: "warn", attempted: 2, passed: 1, fails: 1, programs: []prog{tpAttached, kpFailed}}},
		{LoadAttachRequired, doc{mode: "required", accounting: false, status: "pass", attempted: 1, passed: 1, programs: []prog{tpAttached}}},
		{LoadAttachRequired, doc{mode: "required", accounting: true, breakCounts: true, status: "pass", attempted: 2, passed: 2, programs: []prog{tpAttached, tpAttached2}}},
		{LoadAttachRequired, doc{mode: "required", accounting: true, status: "skipped", programs: []prog{{name: "tp_off", section: "tracepoint/x/y", outcome: "not_selected"}}}},
		{LoadAttachRequired, doc{mode: "required", accounting: true, status: "skipped", loadFail: true, programs: []prog{{name: "tp_a", section: "tracepoint/x/y", outcome: "not_attempted", selected: true}}}},
		{LoadOnly, doc{mode: "disabled", accounting: true, status: "skipped", programs: []prog{{name: "tp_a", section: "tracepoint/x/y", outcome: "not_attempted", selected: true}}}},
	}
	for i, c := range cases {
		data := c.d.bytes(t)
		r, err := parseResult(data, newConfig(WithMode(c.mode)))
		if err != nil {
			t.Fatal(err)
		}
		ev, err := runner.EvaluateValidatorResult(data, c.mode.attachFlag(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != ev.Status || r.Verdict != ev.Verdict || r.FailedStage != ev.FailedStage ||
			r.Classification.Code != ev.ClassificationCode || r.Classification.Reason != ev.ClassificationReason ||
			!reflect.DeepEqual(r.Attach, attachFromValidation(&ev.Validation)) || !reflect.DeepEqual(r.Notes, ev.Notes) ||
			r.Loadable != (ev.Validation.LoadStatus == "pass") {
			t.Errorf("case %d (%v): library %+v differs from runner %+v", i, c.mode, r, ev)
		}
	}
}

// A load that failed because the validator process ran out of file
// descriptors is the validator's environment, not the artifact (as in the
// CLI since #259): infra_error, not INCOMPATIBLE.
func TestLibraryLoadFDLimitIsInfraError(t *testing.T) {
	for _, code := range []int{-24, -23} {
		d := doc{mode: "required", accounting: true, loadFail: true, status: "skipped",
			programs: []prog{{name: "tp_a", section: "tracepoint/x/y", outcome: "not_attempted", selected: true}}}
		var m map[string]any
		if err := json.Unmarshal(d.bytes(t), &m); err != nil {
			t.Fatal(err)
		}
		m["load"] = map[string]any{"status": "fail", "error_code": code, "error": "Too many open files"}
		data, _ := json.Marshal(m)
		r, err := parseResult(data, newConfig(WithMode(LoadAttachRequired)))
		if err != nil {
			t.Fatal(err)
		}
		if r.OK() || r.Compatible() || r.Status != "infra_error" || r.Verdict != schema.VerdictInfraError || r.FailedStage != "infra" {
			t.Fatalf("code %d: got status=%s verdict=%s stage=%s", code, r.Status, r.Verdict, r.FailedStage)
		}
	}
}

// The matrix path carries the engine's attach evidence through unchanged.
func TestResultFromTargetCarriesAttachEvidence(t *testing.T) {
	progs := []schema.AttachProgram{{Name: "tp_a", Selected: true, Outcome: "attached"}, {Name: "xdp_pass", Selected: true, Outcome: "not_attachable_by_validator"}}
	tgt := schema.Target{ProfileID: "p", Status: "unsupported", Verdict: schema.VerdictUnsupported, FailedStage: "attach",
		ClassificationCode: "ATTACH_NOT_EXERCISED", Notes: []string{"attach not fully exercised: 1/2 selected programs attached"},
		Validation: &schema.Validation{LoadStatus: "pass", AttachMode: "required", AttachStatus: "pass", AttachAttempted: 1, AttachPassed: 1,
			AttachAccounting: "v1", AttachCoverage: "partial", AttachEffectiveMode: "required", AttachProgramCount: 2,
			AttachSelected: 2, AttachAttachable: 1, AttachNotAttachable: 1, AttachPrograms: progs}}
	r := resultFromTarget(tgt)
	if !r.OK() || r.Compatible() || r.Status != "unsupported" || r.FailedStage != "attach" || r.Classification.Code != "ATTACH_NOT_EXERCISED" {
		t.Fatalf("got %+v", r)
	}
	if r.Attach.Accounting != "v1" || r.Attach.Coverage != "partial" || !reflect.DeepEqual(r.Attach.Programs, progs) || len(r.Notes) != 1 {
		t.Fatalf("attach = %+v notes=%q", r.Attach, r.Notes)
	}
}

// A target that booted a kernel outside the profile's family has a genuine
// verdict about that kernel, but it cannot establish the requested one: the
// CLI run is INFRA_ERROR, so the library must not call it Compatible.
func TestResultFromTargetWrongKernelFamilyIsNotCompatible(t *testing.T) {
	no, yes := false, true
	tgt := schema.Target{ProfileID: "rhel-8-4.18", Required: true, Status: "pass", Verdict: schema.VerdictCompatible,
		Environment: &schema.EnvironmentCheck{RequestedKernelFamily: "4.18", ObservedKernel: "5.15.0-206.153.7.el8uek.x86_64", KernelFamilyMatch: &no},
		Validation:  &schema.Validation{LoadStatus: "pass"}}
	r := resultFromTarget(tgt)
	if !r.OK() || r.Verdict != schema.VerdictCompatible {
		t.Fatalf("the target's own evidence must be kept: OK=%v verdict=%s", r.OK(), r.Verdict)
	}
	if r.Compatible() {
		t.Fatal("Compatible() must be false when the requested environment was not established")
	}
	if got := schema.RunVerdict([]schema.Target{tgt}); got != schema.VerdictInfraError {
		t.Fatalf("precondition: CLI run verdict = %s, want INFRA_ERROR", got)
	}
	tgt.Environment.KernelFamilyMatch = &yes
	if r := resultFromTarget(tgt); !r.Compatible() {
		t.Fatal("matching kernel family: Compatible() should be true")
	}
	tgt.Environment = nil // older report, unknown: not a mismatch
	if r := resultFromTarget(tgt); !r.Compatible() {
		t.Fatal("unknown environment must not be treated as a mismatch")
	}
}

func TestValidateRefusesRequiredModeWithoutManifestContract(t *testing.T) {
	_, err := Validate(context.Background(), Config{Artifact: "x.bpf.o", Quick: true, Mode: LoadAttachRequired})
	if !errors.Is(err, ErrRequiredModeNeedsManifest) {
		t.Fatalf("err = %v", err)
	}
}

func noteContains(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}
