package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestVerdictForStatusNeverBlamesTheUserForOurFailures(t *testing.T) {
	// The one mapping that must never be wrong: bpfcompat's own failures, and
	// environments it declines to run, are not the user's incompatibility.
	for _, status := range []string{"infra_error", "unsupported"} {
		if got := VerdictForStatus(status); got == VerdictIncompatible {
			t.Fatalf("status %q mapped to %s", status, VerdictIncompatible)
		}
	}
	cases := map[string]string{
		"pass":        VerdictCompatible,
		"fail":        VerdictIncompatible,
		"partial":     VerdictIncompatible,
		"infra_error": VerdictInfraError,
		"unsupported": VerdictUnsupported,
	}
	for status, want := range cases {
		if got := VerdictForStatus(status); got != want {
			t.Errorf("status %q: want %s, got %s", status, want, got)
		}
	}
	// An unrecognised status is a bug somewhere upstream. Failing closed
	// (INCOMPATIBLE) is wrong here -- it would invent a claim about the user's
	// software from a value we do not understand. But silently calling it
	// COMPATIBLE would be worse. The conservative choice is documented by this
	// assertion so a future change is deliberate.
	if got := VerdictForStatus("something-new"); got != VerdictIncompatible {
		t.Fatalf("unknown status should map to %s, got %s", VerdictIncompatible, got)
	}
}

func TestRunVerdictPrecedence(t *testing.T) {
	req := func(v string) Target { return Target{Required: true, Verdict: v} }
	opt := func(v string) Target { return Target{Required: false, Verdict: v} }

	tests := []struct {
		name    string
		targets []Target
		want    string
	}{
		{"all good", []Target{req(VerdictCompatible), opt(VerdictCompatible)}, VerdictCompatible},
		{"required incompatible", []Target{req(VerdictIncompatible)}, VerdictIncompatible},
		{
			// The precedence that matters: a flaky optional VM must not erase a
			// proven regression on a required kernel.
			"required incompatible plus unrelated infra error",
			[]Target{req(VerdictIncompatible), opt(VerdictInfraError)},
			VerdictIncompatible,
		},
		{"infra only", []Target{req(VerdictCompatible), opt(VerdictInfraError)}, VerdictInfraError},
		{"required unsupported", []Target{req(VerdictUnsupported)}, VerdictInfraError},
		{
			// An optional environment we cannot execute is not a run failure.
			"optional unsupported",
			[]Target{req(VerdictCompatible), opt(VerdictUnsupported)},
			VerdictCompatible,
		},
		{
			// An optional target failing compatibility is information, not a gate.
			"optional incompatible",
			[]Target{req(VerdictCompatible), opt(VerdictIncompatible)},
			VerdictCompatible,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RunVerdict(tc.targets); got != tc.want {
				t.Fatalf("want %s, got %s", tc.want, got)
			}
		})
	}
}

func TestRunCompleteTracksUnansweredTargets(t *testing.T) {
	no, yes := false, true
	if !RunComplete([]Target{{Verdict: VerdictCompatible}, {Verdict: VerdictIncompatible}}) {
		t.Fatal("a matrix where every target answered is complete, even when the answer is INCOMPATIBLE")
	}
	if RunComplete([]Target{{Verdict: VerdictInfraError}}) {
		t.Fatal("an infrastructure failure leaves a target unanswered")
	}
	if RunComplete([]Target{{Verdict: VerdictUnsupported}}) {
		t.Fatal("an environment we cannot execute leaves a target unanswered")
	}
	if RunComplete([]Target{{Verdict: VerdictCompatible, Environment: &EnvironmentCheck{KernelFamilyMatch: &no}}}) {
		t.Fatal("a target that booted the wrong kernel series did not cover the requested one")
	}
	if !RunComplete([]Target{{Verdict: VerdictCompatible, Environment: &EnvironmentCheck{KernelFamilyMatch: &yes}}}) {
		t.Fatal("a matching environment is covered")
	}
	if !RunComplete([]Target{{Verdict: VerdictCompatible, Environment: &EnvironmentCheck{}}}) {
		t.Fatal("an unknown match must not be treated as a mismatch")
	}
}

func TestReportSerializesTheContractFields(t *testing.T) {
	// Downstream reads JSON, not Go structs. Every contract field must actually
	// appear -- including exit codes of 0, which `omitempty` used to erase, so
	// "the loader returned 0" and "we never recorded it" looked identical.
	r := ReportV01{
		SchemaVersion: "v0.1",
		Artifact: Artifact{
			Source:       "ghcr.io/org/gadget:latest",
			SourceDigest: "sha256:abc",
			SHA256:       "def",
		},
		Targets: []Target{{
			ProfileID: "ubuntu-22.04-5.15",
			Required:  true,
			Status:    "pass",
			Verdict:   VerdictCompatible,
			Environment: &EnvironmentCheck{
				RequestedKernelFamily: "5.15",
				ObservedKernel:        "5.15.0-186-generic",
				KernelFamilyMatch:     boolPtr(true),
				ImageSHA256:           "img",
			},
			Functional: &Functional{Tests: []FunctionalTest{{ExitCode: 0, ExpectedExitCode: 0}}},
		}},
		Summary: SummaryInfo{Status: "pass", Verdict: VerdictCompatible, Complete: boolPtr(true)},
	}
	blob, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(blob)
	for _, want := range []string{
		`"source_digest":"sha256:abc"`,
		`"verdict":"COMPATIBLE"`,
		`"complete":true`,
		`"kernel_family_match":true`,
		`"observed_kernel":"5.15.0-186-generic"`,
		`"image_sha256":"img"`,
		`"exit_code":0`,
		`"expected_exit_code":0`,
		`"validator_exit":0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report JSON is missing %s\ngot: %s", want, out)
		}
	}

	// A local .bpf.o has no OCI source: those keys must be absent rather than
	// present and empty, so consumers can distinguish "not applicable".
	local, err := json.Marshal(ReportV01{Artifact: Artifact{SHA256: "abc"}})
	if err != nil {
		t.Fatalf("marshal local: %v", err)
	}
	if strings.Contains(string(local), "source_digest") {
		t.Errorf("local artifact must not carry an empty source_digest: %s", local)
	}
}
