package runner

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// attachEvidenceFixtures covers every attach branch: complete, partial,
// unexercised, empty scope, proven failure, accounting unavailable (an old
// validator) and inconsistent accounting, in required and best-effort mode,
// plus a load failure.
func attachEvidenceFixtures() []struct {
	name     string
	mode     string
	required []string
	doc      fakeAttach
} {
	mixed := append(tracingProgs("attached"), fakeProgram{name: "xdp_pass", section: "xdp", outcome: "not_attachable_by_validator", autoload: true})
	failed := append(tracingProgs("attached"), fakeProgram{name: "kp_x", section: "kprobe/does_not_exist", outcome: "failed", autoload: true, errno: -2, detail: "No such file or directory"})
	return []struct {
		name     string
		mode     string
		required []string
		doc      fakeAttach
	}{
		{"required all attached", "required", nil, fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
			selected: 2, attachable: 2, attempted: 2, passed: 2, status: "pass", programs: tracingProgs("attached", "attached")}},
		{"required mixed object", "required", nil, fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
			selected: 2, attachable: 1, notAttachable: 1, attempted: 1, passed: 1, status: "pass", programs: mixed}},
		{"best-effort mixed object", "best-effort", nil, fakeAttach{mode: "best-effort", accounting: true, programCount: 2, records: 2,
			selected: 2, attachable: 1, notAttachable: 1, attempted: 1, passed: 1, status: "pass", programs: mixed}},
		{"required unsupported only", "required", nil, fakeAttach{mode: "required", accounting: true, programCount: 1, records: 1,
			selected: 1, notAttachable: 1, status: "skipped",
			programs: []fakeProgram{{name: "xdp_pass", section: "xdp", outcome: "not_attachable_by_validator", autoload: true}}}},
		{"required empty scope", "required", nil, fakeAttach{mode: "required", accounting: true, programCount: 1, records: 1,
			notSelected: 1, status: "skipped",
			programs: []fakeProgram{{name: "tp_off", section: "tracepoint/x/y", outcome: "not_selected"}}}},
		{"required proven failure", "required", nil, fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
			selected: 2, attachable: 2, attempted: 2, passed: 1, failed: 1, status: "fail", programs: failed}},
		{"best-effort proven failure", "best-effort", nil, fakeAttach{mode: "best-effort", accounting: true, programCount: 2, records: 2,
			selected: 2, attachable: 2, attempted: 2, passed: 1, failed: 1, status: "warn", programs: failed}},
		{"required accounting unavailable (old validator)", "required", nil, fakeAttach{mode: "required", attempted: 1, passed: 1,
			status: "pass", legacyOnly: true, programs: tracingProgs("attached")}},
		{"required contradictory accounting", "required", nil, fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
			selected: 2, attachable: 2, attempted: 2, passed: 2, status: "pass", programs: tracingProgs("attached", "failed")}},
		{"required missing manifest program", "required", []string{"tp_a", "tp_zz"}, fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
			selected: 2, attachable: 2, attempted: 2, passed: 2, status: "pass", programs: tracingProgs("attached", "attached")}},
		{"load failure", "required", nil, fakeAttach{mode: "required", accounting: true, programCount: 1, records: 1,
			selected: 1, attachable: 1, status: "skipped", loadFail: true, programs: tracingProgs("not_attempted")}},
		{"load only", "disabled", nil, fakeAttach{mode: "disabled", accounting: true, programCount: 1, records: 1,
			selected: 1, attachable: 1, status: "skipped", programs: tracingProgs("not_attempted")}},
	}
}

func attachEvidenceNotes(notes []string) []string {
	var out []string
	for _, n := range notes {
		for _, prefix := range []string{"attach ", "classification:", "remediation:", "validator load error", "validator reported failure"} {
			if strings.HasPrefix(n, prefix) {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

// TestEvaluateValidatorResultMatchesExecuteTarget is the parity guard: for
// every fixture, the exported evaluation must reach exactly the target the
// matrix runner builds from the same validator document.
func TestEvaluateValidatorResultMatchesExecuteTarget(t *testing.T) {
	for _, fx := range attachEvidenceFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			doc := fx.doc.json(t)
			want := runAttachTarget(t, fx.mode, validatorTuning{requiredAttachPrograms: fx.required}, doc)
			got, err := EvaluateValidatorResult(doc, fx.mode, fx.required)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != want.Status || got.Verdict != want.Verdict || got.FailedStage != want.FailedStage {
				t.Errorf("status/verdict/stage = %s/%s/%s, runner %s/%s/%s", got.Status, got.Verdict, got.FailedStage, want.Status, want.Verdict, want.FailedStage)
			}
			if got.ClassificationCode != want.ClassificationCode || got.ClassificationConfidence != want.ClassificationConfidence ||
				got.ClassificationReason != want.ClassificationReason {
				t.Errorf("classification = %s/%s/%q, runner %s/%s/%q", got.ClassificationCode, got.ClassificationConfidence,
					got.ClassificationReason, want.ClassificationCode, want.ClassificationConfidence, want.ClassificationReason)
			}
			if got.Status == "infra_error" && got.InfraError != want.InfraError {
				t.Errorf("infra error %q, runner %q", got.InfraError, want.InfraError)
			}
			if want.Validation == nil || !reflect.DeepEqual(got.Validation, *want.Validation) {
				t.Errorf("validation differs:\n got  %+v\n want %+v", got.Validation, want.Validation)
			}
			if g, w := attachEvidenceNotes(got.Notes), attachEvidenceNotes(want.Notes); !reflect.DeepEqual(g, w) {
				t.Errorf("attach notes differ:\n got  %q\n want %q", g, w)
			}
		})
	}
}

// The fixtures must actually exercise the branches the library relies on.
func TestAttachEvidenceFixturesCoverTheContract(t *testing.T) {
	seen := map[string]bool{}
	for _, fx := range attachEvidenceFixtures() {
		ev, err := EvaluateValidatorResult(fx.doc.json(t), fx.mode, fx.required)
		if err != nil {
			t.Fatal(err)
		}
		seen[ev.Status+"/"+ev.ClassificationCode] = true
		seen["accounting="+ev.Validation.AttachAccounting] = true
		seen["coverage="+ev.Validation.AttachCoverage] = true
	}
	for _, want := range []string{
		"pass/", "unsupported/ATTACH_NOT_EXERCISED", "unsupported/ATTACH_SCOPE_EMPTY",
		"infra_error/ATTACH_ACCOUNTING_UNAVAILABLE", "infra_error/ATTACH_ACCOUNTING_INCONSISTENT",
		"fail/ATTACH_FAILED",
		"accounting=" + schema.AttachAccountingV1, "accounting=" + schema.AttachAccountingUnavailable,
		"accounting=" + schema.AttachAccountingInconsistent,
		"coverage=" + schema.AttachCoverageComplete, "coverage=" + schema.AttachCoveragePartial,
		"coverage=" + schema.AttachCoverageNone, "coverage=" + schema.AttachCoverageEmpty,
		"coverage=" + schema.AttachCoverageNotEvaluated,
	} {
		if !seen[want] {
			t.Errorf("no fixture produces %s (seen %v)", want, seen)
		}
	}
}

func TestEvaluateValidatorResultRejectsGarbage(t *testing.T) {
	if _, err := EvaluateValidatorResult([]byte("not json"), "required", nil); err == nil {
		t.Fatal("want a parse error")
	}
}
