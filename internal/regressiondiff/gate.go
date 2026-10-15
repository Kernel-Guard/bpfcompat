package regressiondiff

import (
	"fmt"
	"os"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// NoRequiredComparisonNote marks a diff with no required cell. overallResult
// only counts required cells, so such a diff reports NO_NEW_REGRESSIONS (exit
// 0) even when an optional target regressed. That default is established; the
// note says what it means.
const NoRequiredComparisonNote = "no required comparison: diagnostic diff, not a gate. No cell is required on either side, so the result cannot report a regression; read new_optional_regressions and the cells. Pass --require-gate to exit 1 instead of 0."

// diffGate is "enforced" when at least one cell is required (on either side),
// "none" otherwise -- the diff counterpart of schema.RunGate.
func diffGate(cells []Cell) string {
	for i := range cells {
		if cells[i].Required {
			return schema.GateEnforced
		}
	}
	return schema.GateNone
}

// applyGate records the diff gate, each input's report gate (derived from its
// targets, so reports written before summary.gate existed get one too) and the
// diagnostic note.
func applyGate(d *Diff, baseline, candidate schema.ReportV01) {
	d.Summary.Gate = diffGate(d.Cells)
	d.Summary.BaselineGate = schema.RunGate(baseline.Targets)
	d.Summary.CandidateGate = schema.RunGate(candidate.Targets)
	if d.Summary.Gate == schema.GateNone {
		d.Notes = append(d.Notes, NoRequiredComparisonNote)
	}
}

// GateExitCode applies the opt-in --require-gate contract. Without it the
// established exit code (ExitCode) is returned unchanged. With it, a diff that
// has no required cell exits 1 -- the requested gate was not established --
// and never 2, because nothing about the candidate was proven.
func GateExitCode(d Diff, requireGate bool) int {
	if !requireGate || d.Summary.Gate != schema.GateNone {
		return ExitCode(d)
	}
	fmt.Fprintln(os.Stderr, "--require-gate: no cell is required in either report, so no compatibility gate was compared (summary.gate \"none\"); exiting 1.")
	return ExitInconclusive
}
