package runner

import (
	"strconv"
	"testing"
)

// Per-program records are complete up to an explicit bound shared with the
// validator (MAX_PROGRAM_RECORDS in validator/c-libbpf/src/main.c). Above it
// the records stop at the bound and say so; they are never cut silently.

const validatorRecordBound = 1024 // must equal MAX_PROGRAM_RECORDS

func attachedRecords(n int) []fakeProgram {
	progs := make([]fakeProgram, 0, n)
	for i := 0; i < n; i++ {
		progs = append(progs, fakeProgram{name: "p" + strconv.Itoa(i), section: "tracepoint/a/b", outcome: "attached", autoload: true})
	}
	return progs
}

func TestRunnerRecordBoundMatchesTheValidator(t *testing.T) {
	if maxAttachRecords != validatorRecordBound {
		t.Fatalf("runner bound %d != validator bound %d", maxAttachRecords, validatorRecordBound)
	}
}

func TestFalcoSizedObjectIsRecordedCompletely(t *testing.T) {
	// 206 programs (Falco modern_bpf): every program has a record.
	const n = 206
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: n, records: n,
		selected: n, attachable: n, attempted: n, passed: n, status: "pass", programs: attachedRecords(n),
		overrideTop: map[string]any{"records_bound": validatorRecordBound}}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if got.Validation.AttachAccounting != "v1" || got.Validation.AttachRecordsTruncated ||
		len(got.Validation.AttachPrograms) != n {
		t.Fatalf("accounting=%q truncated=%t records=%d", got.Validation.AttachAccounting,
			got.Validation.AttachRecordsTruncated, len(got.Validation.AttachPrograms))
	}
}

func TestRecordsAtTheBoundAreAcceptedAndMarkedTruncated(t *testing.T) {
	const total = 1100
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: total, records: validatorRecordBound,
		selected: total, attachable: total, attempted: total, passed: total, status: "pass",
		programs:    attachedRecords(validatorRecordBound),
		overrideTop: map[string]any{"records_bound": validatorRecordBound}}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if got.Validation.AttachAccounting != "v1" || !got.Validation.AttachRecordsTruncated ||
		len(got.Validation.AttachPrograms) != validatorRecordBound {
		t.Fatalf("accounting=%q truncated=%t records=%d", got.Validation.AttachAccounting,
			got.Validation.AttachRecordsTruncated, len(got.Validation.AttachPrograms))
	}
}

func TestTruncationBelowTheDeclaredBoundIsInconsistent(t *testing.T) {
	// A validator that declares its bound only stops recording at that bound.
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: 206, records: 64,
		selected: 206, attachable: 206, attempted: 206, passed: 206, status: "pass",
		programs:    attachedRecords(64),
		overrideTop: map[string]any{"records_bound": validatorRecordBound}}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if got.Validation.AttachAccounting != "inconsistent" {
		t.Fatalf("accounting=%q", got.Validation.AttachAccounting)
	}
}

func TestDeclaredBoundAboveTheRunnerBoundIsInconsistent(t *testing.T) {
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: 3, records: 3,
		selected: 3, attachable: 3, attempted: 3, passed: 3, status: "pass",
		programs:    attachedRecords(3),
		overrideTop: map[string]any{"records_bound": validatorRecordBound + 1}}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if got.Validation.AttachAccounting != "inconsistent" {
		t.Fatalf("accounting=%q", got.Validation.AttachAccounting)
	}
}

func TestDeclaredBoundBelowTheRecordCountIsInconsistent(t *testing.T) {
	// 206 complete records cannot come from a validator whose bound is 64.
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: 206, records: 206,
		selected: 206, attachable: 206, attempted: 206, passed: 206, status: "pass",
		programs:    attachedRecords(206),
		overrideTop: map[string]any{"records_bound": 64}}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if got.Validation.AttachAccounting != "inconsistent" {
		t.Fatalf("accounting=%q", got.Validation.AttachAccounting)
	}
}

func TestLegacy64RecordValidatorIsStillReadAsTruncated(t *testing.T) {
	// Validators before the bound (rc.4) write 64 records and no records_bound.
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: 206, records: 64,
		selected: 206, attachable: 206, attempted: 206, passed: 206, status: "pass",
		programs: attachedRecords(64)}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if got.Validation.AttachAccounting != "v1" || !got.Validation.AttachRecordsTruncated {
		t.Fatalf("accounting=%q truncated=%t", got.Validation.AttachAccounting, got.Validation.AttachRecordsTruncated)
	}
}
