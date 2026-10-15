package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

func partialTarget() schema.Target {
	return schema.Target{
		ProfileID: "ubuntu-22.04-5.15", Required: true, Status: "pass", Verdict: schema.VerdictCompatible,
		Validation: &schema.Validation{
			LoadStatus: "pass", AttachMode: "best-effort", AttachStatus: "pass",
			AttachAttempted: 1, AttachPassed: 1,
			AttachAccounting: schema.AttachAccountingV1, AttachCoverage: schema.AttachCoveragePartial,
			AttachProgramCount: 3, AttachSelected: 3, AttachAttachable: 1, AttachNotAttachable: 2,
			AttachPrograms: []schema.AttachProgram{
				{Name: "tp", Section: "tracepoint/a/b", Selected: true, Outcome: schema.AttachOutcomeAttached},
				{Name: "l1", Section: "lsm/file_open", Selected: true, Outcome: schema.AttachOutcomeNotAttachable},
				{Name: "l2|x", Section: "lsm/bprm_check", Selected: true, Outcome: schema.AttachOutcomeNotAttachable},
			},
		},
	}
}

func TestAttachSummaryLine(t *testing.T) {
	got, full := attachSummary(partialTarget().Validation)
	if full {
		t.Fatal("partial coverage reported as full")
	}
	if got != "1/3 attached, 2 not exercised (lsm/ x2)" {
		t.Fatalf("got %q", got)
	}
	complete := &schema.Validation{AttachAccounting: schema.AttachAccountingV1, AttachCoverage: schema.AttachCoverageComplete,
		AttachSelected: 2, AttachAttachable: 2, AttachAttempted: 2, AttachPassed: 2, AttachProgramCount: 2}
	if s, full := attachSummary(complete); !full || s != "2/2 attached" {
		t.Fatalf("got %q full=%t", s, full)
	}
	failed := &schema.Validation{AttachAccounting: schema.AttachAccountingV1, AttachCoverage: schema.AttachCoverageComplete,
		AttachSelected: 2, AttachAttachable: 2, AttachAttempted: 2, AttachPassed: 1, AttachFailed: 1, AttachProgramCount: 2}
	if s, full := attachSummary(failed); full || s != "1/2 attached, 1 failed" {
		t.Fatalf("got %q full=%t", s, full)
	}
	if s, _ := attachSummary(&schema.Validation{AttachAccounting: schema.AttachAccountingUnavailable, AttachCoverage: schema.AttachCoverageUnavailable}); s != "accounting unavailable" {
		t.Fatalf("got %q", s)
	}
	if s, _ := attachSummary(nil); s != "-" {
		t.Fatalf("got %q", s)
	}
}

func TestActionSummaryMarksPartiallyExercisedPass(t *testing.T) {
	r := schema.ReportV01{SchemaVersion: "v0.1", Targets: []schema.Target{partialTarget()},
		Summary: schema.SummaryInfo{Status: "pass", Verdict: schema.VerdictCompatible}}
	out := BuildGitHubActionSummary(r, ActionSummaryOptions{})
	if !strings.Contains(out, "attach not fully exercised") {
		t.Fatalf("COMPATIBLE with unexercised programs carries no marker:\n%s", out)
	}
	if !strings.Contains(out, "1/3 attached, 2 not exercised (lsm/ x2)") {
		t.Fatalf("attach column missing:\n%s", out)
	}
}

func TestMarkdownShowsPerProgramAttachOutcomes(t *testing.T) {
	r := schema.ReportV01{SchemaVersion: "v0.1", Targets: []schema.Target{partialTarget()},
		Summary: schema.SummaryInfo{Status: "pass", Verdict: schema.VerdictCompatible}}
	path := filepath.Join(t.TempDir(), "report.md")
	if err := WriteMarkdown(path, r); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, want := range []string{"attach not fully exercised", "Attach coverage: `partial`", "`not_attachable_by_validator`", `l2\|x`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
