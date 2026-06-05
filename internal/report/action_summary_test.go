package report

import (
	"strings"
	"testing"

	"github.com/erenari/bpfcompat/pkg/schema"
)

func TestBuildGitHubActionSummaryIncludesCountsClassesAndHints(t *testing.T) {
	report := schema.ReportV01{
		Run: schema.RunInfo{ID: "run-1"},
		Artifact: schema.Artifact{
			BaseName: "fentry.bpf.o",
			SHA256:   "1234567890abcdef",
		},
		Matrix: schema.MatrixInfo{Name: "ci-five", Profiles: []string{"ubuntu-18.04-4.15", "ubuntu-20.04-5.4", "ubuntu-22.04-5.15"}},
		Summary: schema.SummaryInfo{
			Status: "fail",
			Notes:  []string{"Compatibility check failed on at least one required profile."},
		},
		Targets: []schema.Target{
			{
				ProfileID:            "ubuntu-18.04-4.15",
				Required:             true,
				Status:               "fail",
				Profile:              &schema.TargetEnv{Kernel: "4.15"},
				BTF:                  &schema.TargetBTF{KernelBTFAvailable: false},
				ClassificationCode:   "MISSING_BTF",
				ClassificationReason: "Artifact appears to require kernel BTF.",
			},
			{
				ProfileID:            "ubuntu-20.04-5.4",
				Required:             true,
				Status:               "fail",
				Profile:              &schema.TargetEnv{Kernel: "5.4"},
				BTF:                  &schema.TargetBTF{KernelBTFAvailable: true},
				ClassificationCode:   "UNSUPPORTED_PROGRAM_TYPE",
				ClassificationReason: "fentry requires fentry/fexit-style tracing support.",
			},
			{
				ProfileID: "ubuntu-22.04-5.15",
				Required:  false,
				Status:    "pass",
				Host:      &schema.TargetEnv{Kernel: "5.15"},
				BTF:       &schema.TargetBTF{KernelBTFAvailable: true},
			},
		},
	}

	summary := BuildGitHubActionSummary(report, ActionSummaryOptions{})
	for _, want := range []string{
		"# bpfcompat Compatibility Gate",
		"**Status:** `fail`",
		"| Required pass/fail | 0/2 |",
		"| Optional pass/fail | 1/0 |",
		"`MISSING_BTF`",
		"`UNSUPPORTED_PROGRAM_TYPE`",
		"avoid fentry/fexit on kernels before 5.5",
		"`ubuntu-18.04-4.15`: `MISSING_BTF`",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}
}

func TestBuildGitHubActionSummaryLimitsTargetsAndFailures(t *testing.T) {
	report := schema.ReportV01{
		Summary: schema.SummaryInfo{Status: "fail"},
		Targets: []schema.Target{
			{ProfileID: "a", Status: "fail", ClassificationCode: "UNKNOWN"},
			{ProfileID: "b", Status: "fail", ClassificationCode: "UNKNOWN"},
			{ProfileID: "c", Status: "pass"},
		},
	}

	summary := BuildGitHubActionSummary(report, ActionSummaryOptions{MaxTargets: 2, MaxFailures: 1})
	for _, want := range []string{
		"Showing 2 of 3 profiles",
		"... 1 more failing target(s)",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}
}
