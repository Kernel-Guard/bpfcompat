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
func VerdictForStatus(status string) string {
	switch status {
	case "pass":
		return VerdictCompatible
	case "infra_error":
		return VerdictInfraError
	case "unsupported":
		return VerdictUnsupported
	case "fail", "partial":
		return VerdictIncompatible
	default:
		return VerdictIncompatible
	}
}

// RunVerdict rolls per-target verdicts up to the run.
//
// A proven incompatibility on a required target wins over an infrastructure
// error elsewhere: it is a definitive fact about the user's software, and
// downgrading it to INFRA_ERROR because an unrelated optional VM failed to boot
// would hide a real regression. Incomplete coverage is reported separately by
// Complete() rather than by erasing the finding.
func RunVerdict(targets []Target) string {
	sawInfra := false
	sawRequiredUnsupported := false
	for i := range targets {
		t := &targets[i]
		switch t.Verdict {
		case VerdictIncompatible:
			if t.Required {
				return VerdictIncompatible
			}
		case VerdictInfraError:
			sawInfra = true
		case VerdictUnsupported:
			if t.Required {
				sawRequiredUnsupported = true
			}
		}
	}
	if sawInfra || sawRequiredUnsupported {
		return VerdictInfraError
	}
	return VerdictCompatible
}

// RunComplete reports whether every target in the matrix actually produced a
// compatibility answer. A COMPATIBLE run with Complete=false means "nothing we
// managed to test was incompatible", not "the whole matrix passed".
func RunComplete(targets []Target) bool {
	for i := range targets {
		t := &targets[i]
		switch t.Verdict {
		case VerdictInfraError, VerdictUnsupported:
			return false
		}
		if t.Environment != nil && t.Environment.KernelFamilyMatch != nil && !*t.Environment.KernelFamilyMatch {
			return false
		}
	}
	return true
}
