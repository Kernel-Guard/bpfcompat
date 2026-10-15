package schema

// Run-level gate states (summary.gate).
//
// RunVerdict rolls up required targets only, so a run whose matrix has no
// required target reports COMPATIBLE whatever its targets did: it is a
// diagnostic execution, not a satisfied compatibility gate. The verdict, the
// status and the exit code of such a run are unchanged (they are established
// contract, and `bpfcompat diff` recomputes the verdict from the targets).
// RunGate is the additive signal that says which kind of run it was.
const (
	// GateEnforced: at least one target is required, so summary.verdict is a
	// compatibility gate over those targets.
	GateEnforced = "enforced"
	// GateNone: no target is required. summary.verdict COMPATIBLE is vacuous;
	// the per-target verdicts are the result.
	GateNone = "none"
)

// NoGateNote is the run-level note for a run with no required target. It
// replaces "All required profiles passed validator load checks.", which is
// vacuously true there and reads as a passed gate.
const NoGateNote = "no required targets: diagnostic run, not a compatibility gate. summary.verdict COMPATIBLE only means no required target failed (there were none); read targets[].verdict for the results."

// RunGate reports whether the run's verdict is a compatibility gate.
func RunGate(targets []Target) string {
	for i := range targets {
		if targets[i].Required {
			return GateEnforced
		}
	}
	return GateNone
}
