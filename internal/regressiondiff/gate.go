package regressiondiff

import (
	"fmt"
	"os"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// NoRequiredComparisonNote marks a diff that compared no gated obligation.
// The established result and exit code are unchanged (overallResult still
// counts cells required on either side); the note says what the diff is.
const NoRequiredComparisonNote = "no required comparison: diagnostic diff, not a gate. No profile is required in both reports, so no gated obligation was compared (a report with no required target is a diagnostic run); read the cells and both report gates. Pass --require-gate to exit 1 instead of 0."

// diffGate is "enforced" only when at least one profile is required in BOTH
// reports: the baseline obligation and the candidate's evaluation of it.
// A diagnostic candidate (or baseline) therefore never makes a gated diff,
// and neither do reports that are each gated but on different profiles.
// It is the diff counterpart of schema.RunGate.
func diffGate(baseline, candidate schema.ReportV01) string {
	required := map[string]bool{}
	for i := range baseline.Targets {
		if baseline.Targets[i].Required {
			required[baseline.Targets[i].ProfileID] = true
		}
	}
	for i := range candidate.Targets {
		if candidate.Targets[i].Required && required[candidate.Targets[i].ProfileID] {
			return schema.GateEnforced
		}
	}
	return schema.GateNone
}

// applyGate records the diff gate, each input's report gate (derived from its
// targets, so reports written before summary.gate existed get one too) and the
// diagnostic note.
func applyGate(d *Diff, baseline, candidate schema.ReportV01) {
	d.Summary.Gate = diffGate(baseline, candidate)
	d.Summary.BaselineGate = schema.RunGate(baseline.Targets)
	d.Summary.CandidateGate = schema.RunGate(candidate.Targets)
	if d.Summary.Gate == schema.GateNone {
		d.Notes = append(d.Notes, NoRequiredComparisonNote)
	}
}

// GateExitCode applies the opt-in --require-gate contract. Without it the
// established exit code (ExitCode) is returned unchanged. With it, a diff
// whose gate is not "enforced" exits 1 -- the requested gate was not
// established -- unless it already exits 2: a proven required regression is
// never masked.
func GateExitCode(d Diff, requireGate bool) int {
	exit := ExitCode(d)
	if !requireGate || d.Summary.Gate == schema.GateEnforced || exit == ExitRegressed {
		return exit
	}
	fmt.Fprintln(os.Stderr, "--require-gate: no profile is required in both reports, so no gated obligation was compared (summary.gate is not \"enforced\"); exiting 1.")
	return ExitInconclusive
}
