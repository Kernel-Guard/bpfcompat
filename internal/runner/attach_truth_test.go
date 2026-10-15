package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Attach truth: a verdict must say how much of the attach contract was
// exercised. A passing attach on one tracing program of an object that also
// carries programs the validator cannot attach is partial coverage, and in
// required mode partial coverage is not a COMPATIBLE answer.

type fakeProgram struct {
	name, section, outcome string
	autoload               bool
	errno                  int
	detail                 string
}

type fakeAttach struct {
	mode                                             string
	accounting                                       bool
	programCount, records                            int
	selected, notSelected, attachable, notAttachable int
	attempted, passed, failed                        int
	status                                           string
	loadFail                                         bool
	programs                                         []fakeProgram
	overrideTop                                      map[string]any
	legacyOnly                                       bool
}

func (f fakeAttach) json(t *testing.T) []byte {
	t.Helper()
	programs := make([]map[string]any, 0, len(f.programs))
	for _, p := range f.programs {
		rec := map[string]any{"name": p.name, "section": p.section, "load_status": "pass"}
		legacy := "skipped"
		switch p.outcome {
		case "attached":
			legacy = "pass"
		case "failed":
			legacy = "fail"
			rec["attach_error"] = p.detail
		}
		rec["attach_status"] = legacy
		if !f.legacyOnly {
			rec["autoload"] = p.autoload
			rec["attach_outcome"] = p.outcome
			rec["attach_errno"] = p.errno
			if p.outcome == "attached" || p.outcome == "failed" {
				rec["attach_operation"] = "bpf_program__attach"
			}
		}
		programs = append(programs, rec)
	}
	attach := map[string]any{
		"mode": f.mode, "status": f.status,
		"attempted": f.attempted, "passed": f.passed, "failed": f.failed,
	}
	if f.accounting {
		attach["accounting"] = "v1"
		attach["effective_mode"] = f.mode
		attach["program_count"] = f.programCount
		attach["records"] = f.records
		attach["selected"] = f.selected
		attach["not_selected"] = f.notSelected
		attach["attachable"] = f.attachable
		attach["not_attachable"] = f.notAttachable
	}
	for k, v := range f.overrideTop {
		attach[k] = v
	}
	status := "pass"
	load := map[string]any{"status": "pass", "error_code": 0, "error": ""}
	if f.loadFail {
		status = "fail"
		load = map[string]any{"status": "fail", "error_code": -22, "error": "Invalid argument"}
	}
	if f.status == "fail" {
		status = "fail"
	}
	doc := map[string]any{
		"schema_version": "v0.1",
		"status":         status,
		"host":           map[string]any{"release": "5.15.0-100-generic", "machine": "x86_64"},
		"load":           load,
		"attach":         attach,
		"discovery":      map[string]any{"programs": programs},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runAttachTarget(t *testing.T, mode string, tuning validatorTuning, result []byte) schema.Target {
	t.Helper()
	dir := t.TempDir()
	vrPath := filepath.Join(dir, "result.json")
	if err := os.WriteFile(vrPath, result, 0o600); err != nil {
		t.Fatal(err)
	}
	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		now := time.Now().UTC()
		return vm.ExecutionResult{
			ProfileID: req.Profile.ID, Status: "pass", ValidatorResultPath: vrPath,
			StartedAt: now, FinishedAt: now,
		}
	})
	required := true
	m := matrix.Matrix{Profiles: []matrix.MatrixProfile{{ID: "ubuntu-22.04-5.15", Required: &required}}}
	targets, _ := executeTargets(context.Background(), baseCfg(), m, dir,
		"/tmp/a.bpf.o", "", "", tuning, "/tmp/validator", mode, nil)
	if len(targets) != 1 {
		t.Fatalf("want one target, got %d", len(targets))
	}
	return targets[0]
}

func tracingProgs(outcomes ...string) []fakeProgram {
	out := make([]fakeProgram, 0, len(outcomes))
	for i, o := range outcomes {
		out = append(out, fakeProgram{name: "tp_" + string(rune('a'+i)), section: "tracepoint/syscalls/sys_enter_getpid", outcome: o, autoload: true})
	}
	return out
}

func notesContain(t schema.Target, sub string) bool {
	for _, n := range t.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func TestRequiredTracingOnlyAllAttachedIsCompatible(t *testing.T) {
	r := fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
		selected: 2, attachable: 2, attempted: 2, passed: 2, status: "pass",
		programs: tracingProgs("attached", "attached")}
	got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
	if got.Verdict != schema.VerdictCompatible {
		t.Fatalf("want COMPATIBLE, got %s (%s)", got.Verdict, got.ClassificationReason)
	}
	if got.Validation.AttachCoverage != "complete" || got.Validation.AttachAccounting != "v1" {
		t.Fatalf("coverage=%q accounting=%q", got.Validation.AttachCoverage, got.Validation.AttachAccounting)
	}
	if len(got.Validation.AttachPrograms) != 2 || got.Validation.AttachPrograms[0].Outcome != "attached" {
		t.Fatalf("per-program records not carried: %+v", got.Validation.AttachPrograms)
	}
}

func TestRequiredUnsupportedOnlyIsNotCompatible(t *testing.T) {
	r := fakeAttach{mode: "required", accounting: true, programCount: 1, records: 1,
		selected: 1, notAttachable: 1, status: "skipped",
		programs: []fakeProgram{{name: "xdp_pass", section: "xdp", outcome: "not_attachable_by_validator", autoload: true}}}
	got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
	if got.Verdict != schema.VerdictUnsupported {
		t.Fatalf("attach required, nothing attachable: want UNSUPPORTED, got %s", got.Verdict)
	}
	if got.ClassificationCode != "ATTACH_NOT_EXERCISED" || got.FailedStage != "attach" {
		t.Fatalf("code=%q stage=%q", got.ClassificationCode, got.FailedStage)
	}
	if got.Validation.LoadStatus != "pass" {
		t.Fatalf("load evidence must be preserved, got load_status=%q", got.Validation.LoadStatus)
	}
	if got.Validation.AttachCoverage != "none" {
		t.Fatalf("coverage=%q", got.Validation.AttachCoverage)
	}
	if !strings.Contains(got.ClassificationReason, "xdp") {
		t.Fatalf("reason must name the unexercised section: %q", got.ClassificationReason)
	}
}

func TestRequiredMixedObjectPartialCoverageIsNotCompatible(t *testing.T) {
	progs := append(tracingProgs("attached"), fakeProgram{name: "xdp_pass", section: "xdp", outcome: "not_attachable_by_validator", autoload: true})
	r := fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
		selected: 2, attachable: 1, notAttachable: 1, attempted: 1, passed: 1, status: "pass", programs: progs}
	got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
	if got.Verdict == schema.VerdictCompatible {
		t.Fatal("a successful tracing attach must not stand in for the XDP program nobody attached")
	}
	if got.Verdict != schema.VerdictUnsupported || got.ClassificationCode != "ATTACH_NOT_EXERCISED" {
		t.Fatalf("want UNSUPPORTED/ATTACH_NOT_EXERCISED, got %s/%s", got.Verdict, got.ClassificationCode)
	}
	if got.Validation.AttachCoverage != "partial" || got.Validation.AttachPassed != 1 {
		t.Fatalf("coverage=%q passed=%d", got.Validation.AttachCoverage, got.Validation.AttachPassed)
	}
}

func TestRequiredMixedWithFailureStaysIncompatible(t *testing.T) {
	progs := append(tracingProgs("failed"), fakeProgram{name: "xdp_pass", section: "xdp", outcome: "not_attachable_by_validator", autoload: true})
	progs[0].errno = -2
	progs[0].detail = "No such file or directory"
	r := fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
		selected: 2, attachable: 1, notAttachable: 1, attempted: 1, failed: 1, status: "fail", programs: progs}
	got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
	if got.Verdict != schema.VerdictIncompatible || got.FailedStage != "attach" {
		t.Fatalf("a proven attach failure must stay INCOMPATIBLE, got %s/%s", got.Verdict, got.FailedStage)
	}
}

func TestRequiredZeroSelectedProgramsIsScopeEmpty(t *testing.T) {
	r := fakeAttach{mode: "required", accounting: true, status: "skipped"}
	got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
	if got.Verdict != schema.VerdictUnsupported || got.ClassificationCode != "ATTACH_SCOPE_EMPTY" {
		t.Fatalf("want UNSUPPORTED/ATTACH_SCOPE_EMPTY, got %s/%s", got.Verdict, got.ClassificationCode)
	}
	if got.Validation.AttachCoverage != "empty" {
		t.Fatalf("coverage=%q", got.Validation.AttachCoverage)
	}
}

func TestRequiredAutoloadDisabledProgramIsOutOfScope(t *testing.T) {
	progs := []fakeProgram{
		{name: "getpid_new", section: "tracepoint/syscalls/sys_enter_getpid", outcome: "attached", autoload: true},
		{name: "getpid_old", section: "tracepoint/syscalls/sys_enter_getpid", outcome: "not_selected", autoload: false},
	}
	r := fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
		selected: 1, notSelected: 1, attachable: 1, attempted: 1, passed: 1, status: "pass", programs: progs}
	got := runAttachTarget(t, "required", validatorTuning{requiredAttachPrograms: []string{"getpid_new"}}, r.json(t))
	if got.Verdict != schema.VerdictCompatible || got.Validation.AttachCoverage != "complete" {
		t.Fatalf("an unselected variant is out of scope: got %s coverage=%q (%s)", got.Verdict, got.Validation.AttachCoverage, got.ClassificationReason)
	}
	if got.Validation.AttachNotSelected != 1 {
		t.Fatalf("not-selected program must still be recorded, got %d", got.Validation.AttachNotSelected)
	}
}

func TestRequiredManifestProgramNotSelectedIsNotCompatible(t *testing.T) {
	progs := []fakeProgram{
		{name: "getpid_new", section: "tracepoint/syscalls/sys_enter_getpid", outcome: "attached", autoload: true},
		{name: "getpid_old", section: "tracepoint/syscalls/sys_enter_getpid", outcome: "not_selected", autoload: false},
	}
	r := fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
		selected: 1, notSelected: 1, attachable: 1, attempted: 1, passed: 1, status: "pass", programs: progs}
	got := runAttachTarget(t, "required", validatorTuning{requiredAttachPrograms: []string{"getpid_old"}}, r.json(t))
	if got.Verdict != schema.VerdictUnsupported || got.ClassificationCode != "ATTACH_NOT_EXERCISED" {
		t.Fatalf("manifest requires a program nobody attached: got %s/%s", got.Verdict, got.ClassificationCode)
	}
	if !strings.Contains(got.ClassificationReason, "getpid_old") {
		t.Fatalf("reason must name the program: %q", got.ClassificationReason)
	}
}

func TestRequiredManifestProgramAbsentFromObjectIsNotCompatible(t *testing.T) {
	r := fakeAttach{mode: "required", accounting: true, programCount: 1, records: 1,
		selected: 1, attachable: 1, attempted: 1, passed: 1, status: "pass", programs: tracingProgs("attached")}
	got := runAttachTarget(t, "required", validatorTuning{requiredAttachPrograms: []string{"not_in_object"}}, r.json(t))
	if got.Verdict == schema.VerdictCompatible {
		t.Fatal("a required program the object does not contain was never attached")
	}
}

func TestAttachFailureAttributionIsConservative(t *testing.T) {
	cases := []struct {
		name       string
		errno      int
		detail     string
		wantCode   string
		wantConf   string
		forbidText []string
	}{
		{"ENOENT is not proof of a missing symbol", -2, "No such file or directory", "ATTACH_FAILED", "low",
			[]string{"missing symbol", "symbol is missing", "tracepoint does not exist"}},
		{"EINVAL is not an unsupported attach type", -22, "Invalid argument", "ATTACH_FAILED", "low", nil},
		{"EPERM is not proven to be a permission problem", -1, "Operation not permitted", "ATTACH_FAILED", "low",
			[]string{"permission denied by policy"}},
		{"EOPNOTSUPP supports unsupported attach type", -95, "Operation not supported", "UNSUPPORTED_ATTACH_TYPE", "medium", nil},
		{"ENOTSUPP supports unsupported attach type", -524, "unknown error (-524)", "UNSUPPORTED_ATTACH_TYPE", "medium", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			progs := []fakeProgram{{name: "kp", section: "kprobe/foo", outcome: "failed", autoload: true, errno: tc.errno, detail: tc.detail}}
			r := fakeAttach{mode: "required", accounting: true, programCount: 1, records: 1,
				selected: 1, attachable: 1, attempted: 1, failed: 1, status: "fail", programs: progs}
			got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
			if got.Verdict != schema.VerdictIncompatible {
				t.Fatalf("verdict %s", got.Verdict)
			}
			if got.ClassificationCode != tc.wantCode || got.ClassificationConfidence != tc.wantConf {
				t.Fatalf("want %s/%s, got %s/%s", tc.wantCode, tc.wantConf, got.ClassificationCode, got.ClassificationConfidence)
			}
			lower := strings.ToLower(got.ClassificationReason)
			for _, f := range tc.forbidText {
				if strings.Contains(lower, f) {
					t.Fatalf("reason claims an unproven cause %q: %q", f, got.ClassificationReason)
				}
			}
			p := got.Validation.AttachPrograms[0]
			if p.Errno != tc.errno || p.Detail != tc.detail || p.Operation != "bpf_program__attach" {
				t.Fatalf("raw evidence not preserved: %+v", p)
			}
			if p.Attribution != "errno_only" || p.ReasonClass == "" {
				t.Fatalf("normalized class must be explicit about its basis: %+v", p)
			}
		})
	}
}

func TestOldValidatorWithoutAccounting(t *testing.T) {
	t.Run("required: not presented as verified", func(t *testing.T) {
		r := fakeAttach{mode: "required", attempted: 1, passed: 1, status: "pass", legacyOnly: true, programs: tracingProgs("attached")}
		got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
		if got.Verdict == schema.VerdictCompatible || got.Verdict == schema.VerdictIncompatible {
			t.Fatalf("missing accounting must neither verify nor blame: got %s", got.Verdict)
		}
		if got.ClassificationCode != "ATTACH_ACCOUNTING_UNAVAILABLE" || got.Validation.AttachAccounting != "unavailable" {
			t.Fatalf("code=%q accounting=%q", got.ClassificationCode, got.Validation.AttachAccounting)
		}
		if got.Validation.LoadStatus != "pass" {
			t.Fatal("load evidence must survive")
		}
	})
	t.Run("required: a proven failure still stands", func(t *testing.T) {
		progs := tracingProgs("failed")
		progs[0].detail = "Invalid argument"
		r := fakeAttach{mode: "required", attempted: 1, failed: 1, status: "fail", legacyOnly: true, programs: progs}
		got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
		if got.Verdict != schema.VerdictIncompatible || got.ClassificationCode != "ATTACH_FAILED" {
			t.Fatalf("got %s/%s", got.Verdict, got.ClassificationCode)
		}
	})
	t.Run("best-effort: verdict unchanged, coverage unknown", func(t *testing.T) {
		r := fakeAttach{mode: "best-effort", attempted: 1, passed: 1, status: "pass", legacyOnly: true, programs: tracingProgs("attached")}
		got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
		if got.Verdict != schema.VerdictCompatible {
			t.Fatalf("got %s", got.Verdict)
		}
		if got.Validation.AttachAccounting != "unavailable" || got.Validation.AttachCoverage != "unavailable" {
			t.Fatalf("accounting=%q coverage=%q", got.Validation.AttachAccounting, got.Validation.AttachCoverage)
		}
		if len(got.Validation.AttachPrograms) != 0 {
			t.Fatal("no per-program accounting may be fabricated for an old validator")
		}
	})
}

func TestBestEffortPartialCoverageIsMarked(t *testing.T) {
	progs := append(tracingProgs("attached"), fakeProgram{name: "xdp_pass", section: "xdp", outcome: "not_attachable_by_validator", autoload: true})
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: 2, records: 2,
		selected: 2, attachable: 1, notAttachable: 1, attempted: 1, passed: 1, status: "pass", programs: progs}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if got.Verdict != schema.VerdictCompatible {
		t.Fatalf("best-effort verdict is unchanged, got %s", got.Verdict)
	}
	if got.Validation.AttachCoverage != "partial" {
		t.Fatalf("coverage=%q", got.Validation.AttachCoverage)
	}
	if !notesContain(got, "attach not fully exercised") {
		t.Fatalf("COMPATIBLE with unexercised programs must carry a visible marker: %v", got.Notes)
	}
}

func TestBestEffortAttachFailureIsMarked(t *testing.T) {
	progs := tracingProgs("attached", "failed")
	progs[1].errno = -2
	progs[1].detail = "No such file or directory"
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: 2, records: 2,
		selected: 2, attachable: 2, attempted: 2, passed: 1, failed: 1, status: "warn", programs: progs}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if got.Verdict != schema.VerdictCompatible {
		t.Fatalf("best-effort verdict is unchanged, got %s", got.Verdict)
	}
	if !notesContain(got, "attach not fully attached") || !notesContain(got, "tp_b") {
		t.Fatalf("a best-effort attach failure must be visible and named: %v", got.Notes)
	}
}

func TestLoadFailurePreservesEvidenceAndSkipsCoverage(t *testing.T) {
	r := fakeAttach{mode: "required", accounting: true, programCount: 1, records: 1, selected: 1, attachable: 1,
		status: "skipped", loadFail: true,
		programs: []fakeProgram{{name: "tp_a", section: "tracepoint/x/y", outcome: "not_attempted", autoload: true}}}
	got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
	if got.Verdict != schema.VerdictIncompatible || got.FailedStage != "load" {
		t.Fatalf("got %s/%s", got.Verdict, got.FailedStage)
	}
	if got.Validation.AttachCoverage != "not_evaluated" {
		t.Fatalf("coverage=%q", got.Validation.AttachCoverage)
	}
}

func TestInconsistentAccountingIsNeverAVerifiedPass(t *testing.T) {
	good := func() fakeAttach {
		return fakeAttach{mode: "required", accounting: true, programCount: 1, records: 1,
			selected: 1, attachable: 1, attempted: 1, passed: 1, status: "pass", programs: tracingProgs("attached")}
	}
	longName := strings.Repeat("n", 4096)
	cases := []struct {
		name   string
		mutate func(*fakeAttach)
	}{
		{"attempted != passed+failed", func(f *fakeAttach) { f.attempted = 2 }},
		{"selected+not_selected != program_count", func(f *fakeAttach) { f.programCount = 3 }},
		{"attachable+not_attachable != selected", func(f *fakeAttach) { f.attachable = 0 }},
		{"attempted > attachable", func(f *fakeAttach) { f.overrideTop = map[string]any{"attachable": 0, "not_attachable": 1} }},
		{"negative count", func(f *fakeAttach) { f.overrideTop = map[string]any{"not_selected": -1, "program_count": 0} }},
		{"records disagree with list", func(f *fakeAttach) { f.records = 2 }},
		{"records exceed program_count", func(f *fakeAttach) { f.programs = tracingProgs("attached", "attached"); f.records = 2 }},
		{"unknown outcome", func(f *fakeAttach) { f.programs[0].outcome = "probably_fine" }},
		{"duplicate program name", func(f *fakeAttach) {
			f.programs = append(f.programs, f.programs[0])
			f.programCount, f.records, f.selected, f.attachable, f.attempted, f.passed = 2, 2, 2, 2, 2, 2
		}},
		{"per-program tally disagrees", func(f *fakeAttach) { f.programs[0].outcome = "not_attachable_by_validator" }},
		{"oversized name", func(f *fakeAttach) { f.programs[0].name = longName }},
		{"empty name", func(f *fakeAttach) { f.programs[0].name = "" }},
		{"effective mode disagrees with request", func(f *fakeAttach) { f.overrideTop = map[string]any{"effective_mode": "best-effort"} }},
		{"unknown accounting version", func(f *fakeAttach) { f.overrideTop = map[string]any{"accounting": "v9"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := good()
			tc.mutate(&f)
			got := runAttachTarget(t, "required", validatorTuning{}, f.json(t))
			if got.Verdict == schema.VerdictCompatible {
				t.Fatal("inconsistent accounting presented as a verified attach pass")
			}
			if got.Validation.AttachAccounting == "v1" {
				t.Fatalf("accounting accepted as v1")
			}
			if got.Verdict != schema.VerdictInfraError {
				t.Fatalf("want INFRA_ERROR (our evidence is broken, not the user's program), got %s", got.Verdict)
			}
			if len(got.Validation.AttachPrograms) > maxAttachRecords {
				t.Fatal("unbounded record list")
			}
			for _, p := range got.Validation.AttachPrograms {
				if len(p.Name) > maxAttachNameBytes || len(p.Detail) > maxAttachDetailBytes {
					t.Fatal("unbounded record field")
				}
			}
		})
	}
}

func TestOversizedRecordListIsRejected(t *testing.T) {
	n := maxAttachRecords + 1
	progs := make([]fakeProgram, 0, n)
	for i := 0; i < n; i++ {
		progs = append(progs, fakeProgram{name: "p" + strconv.Itoa(i), section: "tracepoint/a/b", outcome: "attached", autoload: true})
	}
	r := fakeAttach{mode: "required", accounting: true, programCount: n, records: n,
		selected: n, attachable: n, attempted: n, passed: n, status: "pass", programs: progs}
	got := runAttachTarget(t, "required", validatorTuning{}, r.json(t))
	if got.Validation.AttachAccounting != "inconsistent" || len(got.Validation.AttachPrograms) != 0 {
		t.Fatalf("accounting=%q records=%d", got.Validation.AttachAccounting, len(got.Validation.AttachPrograms))
	}
}

func TestTruncatedRecordsUseCountsNotRecords(t *testing.T) {
	// 70 programs, the validator writes 64 records. Coverage comes from the
	// whole-object counts; a failure beyond the records is still a failure.
	progs := make([]fakeProgram, 0, 64)
	for i := 0; i < 64; i++ {
		progs = append(progs, fakeProgram{name: "p" + strconv.Itoa(i), section: "tracepoint/a/b", outcome: "attached", autoload: true})
	}
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: 70, records: 64,
		selected: 70, attachable: 70, attempted: 70, passed: 69, failed: 1, status: "warn", programs: progs}
	got := runAttachTarget(t, "best-effort", validatorTuning{}, r.json(t))
	if got.Validation.AttachAccounting != "v1" || !got.Validation.AttachRecordsTruncated {
		t.Fatalf("accounting=%q truncated=%t", got.Validation.AttachAccounting, got.Validation.AttachRecordsTruncated)
	}
	if !notesContain(got, "attach not fully attached") || !notesContain(got, "records cover 64 of 70") {
		t.Fatalf("failure outside the records must still be visible: %v", got.Notes)
	}
}
