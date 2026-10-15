package regressiondiff

import (
	"fmt"
	"strings"
)

// Which recorded inputs differ between the two runs of a changed outcome.
//
// The comparison key is the support obligation (profile_id), not the artifact
// and not the exact kernel that booted: release N and N+1 contain different
// artifacts, and a profile's kernel moves within its family as the distribution
// ships updates. A NEW_REGRESSION therefore says the obligation regressed
// between the two runs -- including when only the kernel moved, which is the
// "does my unchanged program still load on the updated kernel" question the
// product exists to answer.
//
// These fields are observations, not causes. They say which of the inputs the
// two reports RECORD differ (and which could not be compared). Inputs the
// reports do not record -- kernel config, boot parameters, image contents
// beyond os-release, the host, timing -- may also differ, so even when only
// the artifact differs among the recorded inputs, that is a narrowing of the
// search, not proof that the artifact caused the outcome.
//
// The values name the category of the recorded difference:
const (
	// AttributionArtifactOnly: among the recorded inputs, only the shipped
	// program differs (artifact sha256; in command mode also the loader).
	AttributionArtifactOnly = "artifact_only"
	// AttributionEnvironmentOnly: the shipped program is recorded as
	// unchanged and the recorded environment (kernel, os) differs.
	AttributionEnvironmentOnly = "environment_only"
	// AttributionValidatorOnly: only the artifact-mode validator differs.
	AttributionValidatorOnly = "validator_only"
	// AttributionMultiple: recorded inputs in more than one category differ.
	AttributionMultiple = "multiple"
	// AttributionNoneRecorded: no recorded input differs.
	AttributionNoneRecorded = "none_recorded"
	// AttributionUnknown: an input that could add a category is not
	// recorded on both sides, so no single category can be stated.
	AttributionUnknown = "unknown"
)

// notRecordedClause is appended to every attribution: the recorded inputs are
// not all the inputs.
const notRecordedClause = "inputs the reports do not record (kernel config, boot parameters, image contents, host, timing) may also differ, so this is a recorded difference, not a proven cause"

// inputCategory groups inputs into what the attribution can name.
var inputCategory = map[string]string{
	"artifact":  "artifact",
	"loader":    "artifact",
	"kernel":    "environment",
	"os":        "environment",
	"validator": "validator",
}

// attribute fills ChangedInputs/UnknownInputs/Attribution for a cell whose
// outcome changed and appends the matching explanation to its reason. The
// classification is left exactly as the comparison decided it.
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
	var changed, unknown, neither []string
	// required inputs must be recorded on both sides; optional ones (absent
	// from older reports) are uncertain only when one side records them.
	compare := func(name, x, y string, required bool) {
		x, y = strings.TrimSpace(x), strings.TrimSpace(y)
		switch {
		case x == "" && y == "" && !required:
			neither = append(neither, name)
		case x == "" || y == "":
			unknown = append(unknown, name)
		case x != y:
			changed = append(changed, name)
		}
	}
	// What the project ships: the artifact, and in command mode its own
	// loader binary, compared as a separate input.
	command := b.LoaderMode == "command" && c.LoaderMode == "command"
	if !command || b.ArtifactSHA256 != "" || c.ArtifactSHA256 != "" {
		compare("artifact", b.ArtifactSHA256, c.ArtifactSHA256, true)
	}
	if command {
		compare("loader", b.LoaderSHA256, c.LoaderSHA256, true)
	}
	compare("kernel", cell.Baseline.ObservedKernel, cell.Candidate.ObservedKernel, true)
	compare("os", osIdentity(cell.Baseline), osIdentity(cell.Candidate), false)
	if b.LoaderMode == "artifact" && c.LoaderMode == "artifact" {
		compare("validator", b.LoaderSHA256, c.LoaderSHA256, false)
	}
	cell.ChangedInputs = changed
	cell.UnknownInputs = unknown

	changedCats := categories(changed)
	// An unknown input matters only if it could add a category the recorded
	// differences do not already name.
	var addsCategory bool
	for _, u := range unknown {
		if !changedCats[inputCategory[u]] {
			addsCategory = true
		}
	}

	kernels := fmt.Sprintf("observed kernel %s -> %s", orDash(cell.Baseline.ObservedKernel), orDash(cell.Candidate.ObservedKernel))
	var parts []string
	switch {
	case len(changedCats) > 1:
		cell.Attribution = AttributionMultiple
		parts = append(parts, fmt.Sprintf("%s differ between the runs (%s); the evidence does not separate their effects",
			joinAnd(changed), kernels))
	case addsCategory:
		cell.Attribution = AttributionUnknown
		if len(changed) > 0 {
			parts = append(parts, fmt.Sprintf("recorded as different: %s (%s)", joinAnd(changed), kernels))
		}
		parts = append(parts, fmt.Sprintf("which recorded inputs differ cannot be fully determined: %s %s recorded on one side only or missing",
			joinAnd(unknown), isAre(unknown)))
	case changedCats["artifact"]:
		cell.Attribution = AttributionArtifactOnly
		parts = append(parts, fmt.Sprintf("among the recorded inputs only the shipped program differs (%s; %s)",
			joinAnd(changed), kernels))
	case changedCats["environment"]:
		cell.Attribution = AttributionEnvironmentOnly
		parts = append(parts, fmt.Sprintf("the shipped program is recorded as unchanged and the recorded environment differs (%s): the obligation %s with the same program",
			kernels, outcome))
	case changedCats["validator"]:
		cell.Attribution = AttributionValidatorOnly
		parts = append(parts, "among the recorded inputs only the bpfcompat validator (the measuring instrument) differs")
	default:
		cell.Attribution = AttributionNoneRecorded
		parts = append(parts, fmt.Sprintf("no recorded input differs (%s): the same recorded program and environment produced a different outcome", kernels))
	}
	if len(unknown) > 0 && cell.Attribution != AttributionUnknown {
		parts = append(parts, fmt.Sprintf("%s %s recorded on one side only", joinAnd(unknown), isAre(unknown)))
	}
	for _, n := range neither {
		parts = append(parts, n+" identity is not recorded by either run")
	}
	parts = append(parts, notRecordedClause)
	cell.Reason += "; " + strings.Join(parts, "; ")
}

func categories(inputs []string) map[string]bool {
	m := map[string]bool{}
	for _, in := range inputs {
		m[inputCategory[in]] = true
	}
	return m
}

func isAre(items []string) string {
	if len(items) == 1 {
		return "is"
	}
	return "are"
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
