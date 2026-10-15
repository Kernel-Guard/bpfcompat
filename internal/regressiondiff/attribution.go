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
	var outcome string
	switch cell.Classification {
	case NewRegression:
		outcome = "regressed"
	case Fixed:
		outcome = "was fixed"
	default:
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
	// What the project ships: the artifact, and in command mode its own
	// loader binary, compared as a separate input.
	command := b.LoaderMode == "command" && c.LoaderMode == "command"
	if !command || b.ArtifactSHA256 != "" || c.ArtifactSHA256 != "" {
		compare("artifact", b.ArtifactSHA256, c.ArtifactSHA256)
	}
	if command {
		compare("loader", b.LoaderSHA256, c.LoaderSHA256)
	}
	compare("kernel", cell.Baseline.ObservedKernel, cell.Candidate.ObservedKernel)
	// The os-release identity and the artifact-mode validator are compared
	// only when both sides record them; older reports carry neither.
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
		cell.Reason += fmt.Sprintf("; neither the shipped program nor the observed environment is recorded as changed (%s)", kernels)
	case only(changed, "artifact", "loader"):
		cell.Attribution = AttributionArtifact
		cell.Reason += fmt.Sprintf("; only the shipped program changed (%s; %s), so the change follows it",
			strings.Join(changed, " and "), kernels)
	case only(changed, "kernel", "os"):
		cell.Attribution = AttributionEnvironment
		cell.Reason += fmt.Sprintf("; the shipped program is unchanged and the environment moved (%s): the obligation %s on the newer environment, not through a change to the program",
			kernels, outcome)
	case only(changed, "validator"):
		cell.Attribution = AttributionValidator
		cell.Reason += "; only the bpfcompat validator changed, so the change follows the measuring instrument, not the shipped program or the environment"
	default:
		cell.Attribution = AttributionMultiple
		cell.Reason += fmt.Sprintf("; %s changed between the runs (%s), so the change cannot be attributed to any one of them",
			joinAnd(changed), kernels)
	}
}

// only reports whether every changed input is one of allowed.
func only(changed []string, allowed ...string) bool {
	if len(changed) == 0 {
		return false
	}
	for _, c := range changed {
		ok := false
		for _, a := range allowed {
			if c == a {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}

func osIdentity(s CellSide) string {
	if strings.TrimSpace(s.ObservedOSID) == "" {
		return ""
	}
	return s.ObservedOSID + " " + s.ObservedOSVersionID
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
