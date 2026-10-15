package regressiondiff

import (
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// summary.gate is derived from the targets like summary.verdict and
// summary.complete, so a report whose gate claim disagrees with its own
// targets is refused rather than carried forward.
func TestContradictoryGateIsRefused(t *testing.T) {
	C := schema.VerdictCompatible
	for _, tc := range []struct {
		name   string
		report func() schema.ReportV01
	}{
		{"claims a gate over optional-only targets", func() schema.ReportV01 {
			r := report(target("k", C, false))
			r.Summary.Gate = schema.GateEnforced
			return r
		}},
		{"claims no gate over a required target", func() schema.ReportV01 {
			r := report(target("k", C, true))
			r.Summary.Gate = schema.GateNone
			return r
		}},
		{"unknown gate value", func() schema.ReportV01 {
			r := report(target("k", C, true))
			r.Summary.Gate = "maybe"
			return r
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, _ := greenPair(t)
			_, exit, err := compareFiles(t, base, jsonOf(t, tc.report()))
			if err == nil || !strings.Contains(err.Error(), "summary.gate") {
				t.Fatalf("want a summary.gate refusal, got %v", err)
			}
			if exit != ExitInconclusive {
				t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
			}
		})
	}
}

// A consistent gate field, and its absence (reports written before it
// existed), are both accepted.
func TestConsistentOrAbsentGateIsAccepted(t *testing.T) {
	C := schema.VerdictCompatible
	for _, gate := range []string{"", schema.GateEnforced} {
		base, _ := greenPair(t)
		r := report(target("k", C, true))
		r.Summary.Gate = gate
		if _, _, err := compareFiles(t, base, jsonOf(t, r)); err != nil {
			t.Fatalf("gate %q: unexpected refusal: %v", gate, err)
		}
	}
}
