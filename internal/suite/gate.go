package suite

import (
	"fmt"
	"strings"

	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Suite gate contract (docs/gate-contract.md).
//
// Per case, CaseSummary.Gate is the case report's gate, derived from its
// targets with schema.RunGate: "enforced" (at least one required target) or
// "none" (a diagnostic case whose pass is vacuous). A case that produced no
// report has no evidence of a gate: GateUnknown.
//
// In aggregate, Summary.Gate is "enforced" only when every case is enforced,
// GatePartial when some are, GateUnknown when none are and at least one case
// has no gate evidence, and "none" when every case is a diagnostic case.
// Unknown never counts as enforced, so missing evidence cannot make a suite
// look gated.
//
// Default exit codes are unchanged. With RunOptions.RequireGate, every case
// must evaluate a gate: a case whose gate is not "enforced" exits 1, which the
// suite's existing precedence (tool error over compatibility failure) rolls up
// to exit 1. A gated case keeps its exit code, including 2.
const (
	GatePartial = "partial"
	GateUnknown = "unknown"
)

// executeBootstrapFn runs one case; a package variable so tests can stub the
// executor while exercising the real suite aggregation.
var executeBootstrapFn = runner.ExecuteBootstrap

const requireGateCaseError = "--require-gate: this case has no required target, so no compatibility gate was evaluated (gate none); its report holds diagnostic per-target results"

func applyCaseGate(c CaseSummary, requireGate bool) CaseSummary {
	if c.Gate == "" {
		c.Gate = GateUnknown
	}
	if requireGate && c.Gate == schema.GateNone && c.ExitCode == runner.ExitSuccess {
		c.Status = "error"
		c.ExitCode = runner.ExitToolError
		c.Error = requireGateCaseError
	}
	return c
}

func aggregateGate(cases []CaseSummary) string {
	if len(cases) == 0 {
		return GateUnknown
	}
	enforced, unknown := 0, 0
	for i := range cases {
		switch cases[i].Gate {
		case schema.GateEnforced:
			enforced++
		case schema.GateNone:
		default:
			unknown++
		}
	}
	switch {
	case enforced == len(cases):
		return schema.GateEnforced
	case enforced > 0:
		return GatePartial
	case unknown > 0:
		return GateUnknown
	default:
		return schema.GateNone
	}
}

// writeSuiteGate puts the gate next to the suite status, so a diagnostic
// suite is not read as a satisfied gate.
func writeSuiteGate(b *strings.Builder, gate string) {
	switch gate {
	case "":
		return
	case schema.GateEnforced:
		b.WriteString("- Gate: `enforced` (every case has a required target)\n")
	case schema.GateNone:
		b.WriteString("- Gate: `none` — no case has a required target: diagnostic suite, not a compatibility gate\n")
	case GatePartial:
		b.WriteString("- Gate: `partial` — some cases have no required target (Gate `none` below): those cases are diagnostic, not a compatibility gate\n")
	default:
		fmt.Fprintf(b, "- Gate: `%s` — no case evaluated a gate, and at least one case produced no report (no gate evidence)\n", markdownCell(gate))
	}
}
