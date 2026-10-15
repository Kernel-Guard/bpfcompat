package main

import (
	"fmt"
	"os"

	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// gateExitCode applies the opt-in --require-gate contract to a finished run.
//
// By default the established exit codes are returned unchanged: 0 COMPATIBLE,
// 2 INCOMPATIBLE, 1 tool error / INFRA_ERROR. A run with no required target
// therefore exits 0 -- it is a diagnostic run whose verdict is vacuous
// (summary.gate "none"). With requireGate, such a run exits 1: the caller
// asked for a compatibility gate and none was evaluated. That is an
// unestablished contract, the same class as INFRA_ERROR, never exit 2, since
// nothing was proven about the artifact. The report is still written in full.
func gateExitCode(result runner.RunResult, requireGate bool) int {
	if !requireGate || schema.RunGate(result.Report.Targets) != schema.GateNone {
		return result.ExitCode
	}
	fmt.Fprintln(os.Stderr, "--require-gate: the matrix has no required target, so no compatibility gate was evaluated (summary.gate \"none\"); exiting 1. The report holds the diagnostic per-target results.")
	return runner.ExitToolError
}
