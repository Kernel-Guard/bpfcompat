package report

import (
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// The job summary is what a maintainer reads. A run with no required target
// reports COMPATIBLE whatever happened, so the summary must say that no gate
// was evaluated. It is computed from the targets, so it also holds for
// reports written before summary.gate existed.
func TestActionSummaryMarksOptionalOnlyRunAsNoGate(t *testing.T) {
	r := schema.ReportV01{
		Summary: schema.SummaryInfo{Status: "pass", Verdict: schema.VerdictCompatible},
		Targets: []schema.Target{
			{ProfileID: "rhcos-4.16-5.14", Required: false, Status: "fail", Verdict: schema.VerdictIncompatible},
		},
	}
	got := BuildGitHubActionSummary(r, ActionSummaryOptions{})
	if !strings.Contains(got, "**Gate:** `none`") || !strings.Contains(got, "not a compatibility gate") {
		t.Fatalf("summary must state no gate was evaluated:\n%s", got)
	}
}

func TestActionSummaryGatedRunHasNoNoGateLine(t *testing.T) {
	r := schema.ReportV01{
		Summary: schema.SummaryInfo{Status: "pass", Verdict: schema.VerdictCompatible},
		Targets: []schema.Target{{ProfileID: "k", Required: true, Status: "pass", Verdict: schema.VerdictCompatible}},
	}
	if got := BuildGitHubActionSummary(r, ActionSummaryOptions{}); strings.Contains(got, "**Gate:** `none`") {
		t.Fatalf("a gated run must not be labelled no-gate:\n%s", got)
	}
}
