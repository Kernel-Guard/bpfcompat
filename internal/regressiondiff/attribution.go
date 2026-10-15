package regressiondiff

import (
	"fmt"
	"strings"
)

// Attribution of a changed outcome.
//
// The comparison key is the support obligation (profile_id), not the artifact
// and not the exact kernel that booted: release N and N+1 contain different
// artifacts, and a profile's kernel moves within its family as the distribution
// ships updates. A NEW_REGRESSION therefore says the obligation regressed
// between the two runs -- including when only the kernel moved, which is the
// "does my unchanged program still load on the updated kernel" question the
// product exists to answer. What it does not say on its own is *why*. These
// fields record which inputs differ, so the reason never blames the artifact
// for a change that the environment (or both) could equally explain.
const (
	AttributionArtifact     = "artifact"
	AttributionEnvironment  = "environment"
	AttributionValidator    = "validator"
	AttributionMultiple     = "multiple"
	AttributionNoneRecorded = "none_recorded"
	AttributionUnknown      = "unknown"
)

// attribute fills ChangedInputs/Attribution for a cell whose outcome changed
// and appends the matching explanation to its reason. The classification is
// left exactly as the comparison decided it.
func attribute(cell *Cell, b, c ReportRef) {
	if cell.Classification != NewRegression && cell.Classification != Fixed {
		return
	}
	var changed, missing []string
	compare := func(name, x, y string) {
		x, y = strings.TrimSpace(x), strings.TrimSpace(y)
		switch {
		case x == "" || y == "":
			missing = append(missing, name)
		case x != y:
			changed = append(changed, name)
		}
	}
	compare("artifact", releasedIdentity(b), releasedIdentity(c))
	compare("kernel", cell.Baseline.ObservedKernel, cell.Candidate.ObservedKernel)
	// The os-release identity and the validator are compared only when both
	// sides record them; older reports carry neither.
	if bo, co := osIdentity(cell.Baseline), osIdentity(cell.Candidate); bo != "" && co != "" && bo != co {
		changed = append(changed, "os")
	}
	if b.LoaderMode == "artifact" && c.LoaderMode == "artifact" &&
		b.LoaderSHA256 != "" && c.LoaderSHA256 != "" && b.LoaderSHA256 != c.LoaderSHA256 {
		changed = append(changed, "validator")
	}
	cell.ChangedInputs = changed

	kernels := fmt.Sprintf("observed kernel %s -> %s", orDash(cell.Baseline.ObservedKernel), orDash(cell.Candidate.ObservedKernel))
	switch {
	case len(missing) > 0:
		cell.Attribution = AttributionUnknown
		cell.Reason += fmt.Sprintf("; which input changed cannot be determined: %s not recorded on both sides",
			strings.Join(missing, " and "))
	case len(changed) == 0:
		cell.Attribution = AttributionNoneRecorded
		cell.Reason += fmt.Sprintf("; neither the artifact nor the observed environment is recorded as changed (same artifact, %s)", kernels)
	case len(changed) == 1 && changed[0] == "artifact":
		cell.Attribution = AttributionArtifact
		cell.Reason += fmt.Sprintf("; only the artifact changed (%s), so the change follows the artifact", kernels)
	case onlyEnvironment(changed):
		cell.Attribution = AttributionEnvironment
		cell.Reason += fmt.Sprintf("; the artifact is unchanged and the environment moved (%s): the obligation regressed on the newer environment, not through an artifact change", kernels)
	case len(changed) == 1 && changed[0] == "validator":
		cell.Attribution = AttributionValidator
		cell.Reason += "; only the bpfcompat validator changed, so the change follows the measuring instrument, not the artifact or the environment"
	default:
		cell.Attribution = AttributionMultiple
		cell.Reason += fmt.Sprintf("; %s all changed between the runs (%s), so the change cannot be attributed to the artifact alone",
			strings.Join(changed, ", "), kernels)
	}
}

// releasedIdentity is what the project ships: the artifact, and in command
// mode its own loader binary as well.
func releasedIdentity(r ReportRef) string {
	if r.LoaderMode == "command" {
		if r.ArtifactSHA256 == "" && r.LoaderSHA256 == "" {
			return ""
		}
		return "artifact:" + r.ArtifactSHA256 + " loader:" + r.LoaderSHA256
	}
	return r.ArtifactSHA256
}

func osIdentity(s CellSide) string {
	if strings.TrimSpace(s.ObservedOSID) == "" {
		return ""
	}
	return s.ObservedOSID + " " + s.ObservedOSVersionID
}

func onlyEnvironment(changed []string) bool {
	for _, c := range changed {
		if c != "kernel" && c != "os" {
			return false
		}
	}
	return len(changed) > 0
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
