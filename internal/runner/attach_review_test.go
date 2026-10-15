package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Counterexamples from the independent review of the attach-truth change.
// Each is a validator record the shipped validator does not write, which the
// first version accepted and turned into a green or over-attributed answer.

func TestRequiredModeNeverPassesWithARecordedAttachFailure(t *testing.T) {
	// Overall status "pass" while the counts record a failed attach: the
	// record contradicts itself, and must not reach COMPATIBLE.
	progs := tracingProgs("attached", "failed")
	progs[1].errno = -22
	progs[1].detail = "Invalid argument"
	r := fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
		selected: 2, attachable: 2, attempted: 2, passed: 1, failed: 1, status: "warn", programs: progs}
	got := runAttachTarget(t, "required", validatorTuning{requiredAttachPrograms: []string{"tp_a"}}, r.json(t))
	if got.Verdict == schema.VerdictCompatible {
		t.Fatal("required mode COMPATIBLE with attach_failed=1")
	}
	if got.Validation.AttachAccounting != schema.AttachAccountingInconsistent {
		t.Fatalf("accounting=%q", got.Validation.AttachAccounting)
	}
}

func TestAttachStatusMustAgreeWithCounts(t *testing.T) {
	cases := []struct {
		name string
		f    fakeAttach
	}{
		{"best-effort failure reported as pass", fakeAttach{mode: "best-effort", accounting: true, programCount: 1, records: 1,
			selected: 1, attachable: 1, attempted: 1, failed: 1, status: "pass",
			programs: []fakeProgram{{name: "a", section: "kprobe/x", outcome: "failed", autoload: true, errno: -2}}}},
		{"clean attach reported as warn", fakeAttach{mode: "best-effort", accounting: true, programCount: 1, records: 1,
			selected: 1, attachable: 1, attempted: 1, passed: 1, status: "warn", programs: tracingProgs("attached")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runAttachTarget(t, tc.f.mode, validatorTuning{}, tc.f.json(t))
			if got.Validation.AttachAccounting != schema.AttachAccountingInconsistent {
				t.Fatalf("accounting=%q", got.Validation.AttachAccounting)
			}
		})
	}
}

func TestAttachPhaseMustRunWhenLoadPassedAndModeIsOn(t *testing.T) {
	// load passed, best-effort, one attachable program, nothing attempted:
	// the attach phase claims it did not run when it must have.
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: 1, records: 1,
		selected: 1, attachable: 1, status: "skipped", programs: tracingProgs("not_attempted")}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if got.Validation.AttachAccounting != schema.AttachAccountingInconsistent {
		t.Fatalf("accounting=%q coverage=%q", got.Validation.AttachAccounting, got.Validation.AttachCoverage)
	}
}

func TestTruncatedFailuresAreNotAttributedFromAPartialView(t *testing.T) {
	t.Run("one of two failures recorded, EOPNOTSUPP", func(t *testing.T) {
		progs := tracingProgs("failed")
		progs[0].errno = -95
		progs[0].detail = "Operation not supported"
		r := fakeAttach{mode: "required", accounting: true, programCount: 2, records: 1,
			selected: 2, attachable: 2, attempted: 2, failed: 2, status: "fail", programs: progs}
		got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
		if got.ClassificationCode != "ATTACH_FAILED" || got.ClassificationConfidence != "low" {
			t.Fatalf("an unseen failure cannot be called an unsupported attach type: %s/%s", got.ClassificationCode, got.ClassificationConfidence)
		}
		if !strings.Contains(got.ClassificationReason, "1 of 2") {
			t.Fatalf("reason must say only part of the failures are recorded: %q", got.ClassificationReason)
		}
	})
	t.Run("no failure inside the records", func(t *testing.T) {
		r := fakeAttach{mode: "required", accounting: true, programCount: 2, records: 1,
			selected: 2, attachable: 2, attempted: 2, passed: 1, failed: 1, status: "fail", programs: tracingProgs("attached")}
		got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
		if got.Verdict != schema.VerdictIncompatible {
			t.Fatalf("verdict %s", got.Verdict)
		}
		if strings.Contains(got.ClassificationReason, "recorded no per-program errno") || !strings.Contains(got.ClassificationReason, "0 of 1") {
			t.Fatalf("reason misstates the evidence: %q", got.ClassificationReason)
		}
	})
}

func TestRunNoteNamesUnexercisedRequiredAttach(t *testing.T) {
	r := fakeAttach{mode: "required", accounting: true, programCount: 1, records: 1,
		selected: 1, notAttachable: 1, status: "skipped",
		programs: []fakeProgram{{name: "xdp_pass", section: "xdp", outcome: "not_attachable_by_validator", autoload: true}}}
	dir := t.TempDir()
	vrPath := filepath.Join(dir, "result.json")
	if err := os.WriteFile(vrPath, r.json(t), 0o600); err != nil {
		t.Fatal(err)
	}
	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		now := time.Now().UTC()
		return vm.ExecutionResult{ProfileID: req.Profile.ID, Status: "pass", ValidatorResultPath: vrPath, StartedAt: now, FinishedAt: now}
	})
	required := true
	m := matrix.Matrix{Profiles: []matrix.MatrixProfile{{ID: "ubuntu-22.04-5.15", Required: &required}}}
	_, notes := executeTargets(context.Background(), baseCfg(), m, dir, "/tmp/a.bpf.o", "", "", validatorTuning{}, "/tmp/validator", "required", nil)
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "attach was not fully exercised") {
		t.Fatalf("run notes do not explain the unexercised attach: %v", notes)
	}
	if strings.Contains(joined, "booted a kernel other than") {
		t.Fatalf("run note blames execution/environment for an attach-coverage gap: %v", notes)
	}
}

func TestReasonClassNamesTheErrnoNotACause(t *testing.T) {
	progs := []fakeProgram{{name: "kp", section: "kprobe/foo", outcome: "failed", autoload: true, errno: -2, detail: "No such file or directory"}}
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: 1, records: 1,
		selected: 1, attachable: 1, attempted: 1, failed: 1, status: "warn", programs: progs}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if c := got.Validation.AttachPrograms[0].ReasonClass; c != "ERRNO_ENOENT" {
		t.Fatalf("reason_class=%q", c)
	}
	if !notesContain(got, "attach not fully attached") && !notesContain(got, "not fully attached") {
		t.Fatalf("a tried-and-failed program is not 'not exercised': %v", got.Notes)
	}
}
