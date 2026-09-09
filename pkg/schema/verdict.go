package schema

// The verdict taxonomy is the product compatibility contract: it separates a
// statement about the user's software from a statement about bpfcompat itself.
//
// It exists alongside the older `status` field rather than replacing it.
// `status` (pass/fail/infra_error) is what already-merged downstream
// integrations read, and the schema stability contract only permits additive
// change within a major. `verdict` is the field new consumers should gate on;
// `status` keeps its current meaning.
const (
	// VerdictCompatible: the requested contract executed and the artifact or
	// loader satisfied it on this environment.
	VerdictCompatible = "COMPATIBLE"

	// VerdictIncompatible: the environment executed far enough to establish
	// that the user's artifact or loader does not satisfy the contract. This is
	// a statement about the user's software.
	VerdictIncompatible = "INCOMPATIBLE"

	// VerdictInfraError: bpfcompat could not establish compatibility because
	// its own execution pipeline failed -- image download, boot, guest
	// transport, timeout, internal error. This is never a statement about the
	// user's software.
	VerdictInfraError = "INFRA_ERROR"

	// VerdictUnsupported: bpfcompat intentionally cannot execute this
	// environment (no supported execution transport for the profile). Also not
	// a statement about the user's software -- the contract was never
	// exercised, so nothing was proven either way.
	VerdictUnsupported = "UNSUPPORTED"
)

// VerdictForStatus maps a per-target `status` to its verdict. Kept as one
// function so the two fields cannot drift apart.
//
// An unrecognised status maps to INFRA_ERROR, not INCOMPATIBLE. Every status the
// runner produces today is one of the four below, so this is unreachable from
// our own execution paths -- but this function is exported from pkg/, is reached
// by anything unmarshalling a report written by a different bpfcompat version,
// and would be reached by any future producer that adds a status without
// updating this switch. In all of those cases what we know is "bpfcompat does
// not understand this state", which is not evidence that the user's program
// failed to load. Guessing INCOMPATIBLE would blame their software for our own
// gap; INFRA_ERROR still fails closed and still fails CI, without assigning
// fault.
func VerdictForStatus(status string) string {
	switch status {
	case "pass":
		return VerdictCompatible
	case "infra_error":
		return VerdictInfraError
	case "unsupported":
		return VerdictUnsupported
	case "fail", "partial":
		// Both are real execution evidence about the artifact: it was loaded and
		// the loader reported failure or partial success.
		return VerdictIncompatible
	default:
		return VerdictInfraError
	}
}

// EstablishedRequestedEnvironment reports whether this target actually exercised
// the environment the profile asked for. A guest that booted a different kernel
// series produces a genuine result about the kernel it ran -- but it cannot
// support a claim about the one that was requested.
func EstablishedRequestedEnvironment(t *Target) bool {
	if t.Environment == nil || t.Environment.KernelFamilyMatch == nil {
		// Unknown, not mismatched: an older report, or a target that never
		// reported a kernel. Do not invent a failure from missing data.
		return true
	}
	return *t.Environment.KernelFamilyMatch
}

// RunVerdict rolls per-target verdicts up to the run.
//
// Two rules govern it.
//
// `required` decides gating, for every outcome and not only for compatibility
// failures. A profile marked `required: false` is documented as one whose
// failure does not fail the gate; letting an optional VM that failed to boot
// set the run's exit code would make it required in everything but name. So
// only required targets are considered here. What was lost is still reported --
// by RunComplete, and per target -- rather than by blocking the release.
//
// A proven incompatibility on a required target outranks an infrastructure
// error: it is a definitive fact about the user's software, and downgrading it
// because some other VM failed would hide a real regression behind a flaky
// runner.
func RunVerdict(targets []Target) string {
	cannotEstablish := false
	for i := range targets {
		t := &targets[i]
		if !t.Required {
			continue
		}
		switch t.Verdict {
		case VerdictIncompatible:
			return VerdictIncompatible
		case VerdictInfraError, VerdictUnsupported:
			cannotEstablish = true
		case VerdictCompatible:
			// A required target that passed on a kernel other than the one the
			// profile requested has not established the requested contract. The
			// artifact result stands for the kernel that booted, but the run
			// must not exit 0 claiming support for a series nothing tested.
			// This is our environment failing to be what we asked for, not the
			// user's program failing, so it is INFRA_ERROR and never
			// INCOMPATIBLE.
			if !EstablishedRequestedEnvironment(t) {
				cannotEstablish = true
			}
		}
	}
	if cannotEstablish {
		return VerdictInfraError
	}
	return VerdictCompatible
}

// RunComplete reports whether every target in the matrix actually produced an
// answer about the environment it was asked about. Unlike RunVerdict this spans
// optional targets too: coverage is a description of what was tested, not a
// gating decision. A COMPATIBLE run with Complete=false means "nothing we
// managed to test was incompatible", not "the whole matrix passed".
func RunComplete(targets []Target) bool {
	for i := range targets {
		t := &targets[i]
		switch t.Verdict {
		case VerdictInfraError, VerdictUnsupported:
			return false
		}
		if !EstablishedRequestedEnvironment(t) {
			return false
		}
	}
	return true
}
