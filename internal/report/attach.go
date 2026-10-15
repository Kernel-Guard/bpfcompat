package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// notFullyExercisedMarker is appended to a passing target whose selected
// programs were not all attached: some were not exercised, or failed under
// best-effort.
const notFullyExercisedMarker = "attach not fully exercised"

// attachSummary renders a target's attach accounting in one line, e.g.
// "3/5 attached, 2 not exercised (lsm/ x2)". full reports whether every
// selected program was attempted and attached.
func attachSummary(v *schema.Validation) (summary string, full bool) {
	if v == nil {
		return "-", false
	}
	switch v.AttachAccounting {
	case schema.AttachAccountingV1:
	case schema.AttachAccountingUnavailable, schema.AttachAccountingInconsistent:
		return "accounting " + v.AttachAccounting, false
	default:
		return "-", false
	}
	switch v.AttachCoverage {
	case schema.AttachCoverageNotEvaluated:
		return "not evaluated", false
	case schema.AttachCoverageEmpty:
		return "no programs selected", false
	}
	parts := []string{fmt.Sprintf("%d/%d attached", v.AttachPassed, v.AttachSelected)}
	if v.AttachFailed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", v.AttachFailed))
	}
	if notExercised := v.AttachSelected - v.AttachAttempted; notExercised > 0 {
		parts = append(parts, fmt.Sprintf("%d not exercised (%s)", notExercised, unexercisedKinds(v)))
	}
	full = v.AttachCoverage == schema.AttachCoverageComplete && v.AttachFailed == 0 && v.AttachPassed == v.AttachSelected
	return strings.Join(parts, ", "), full
}

// notFullyExercised reports whether a passing target should carry the marker.
func notFullyExercised(t *schema.Target) bool {
	if t == nil || t.Validation == nil || t.Validation.AttachAccounting != schema.AttachAccountingV1 {
		return false
	}
	switch t.Validation.AttachCoverage {
	case schema.AttachCoverageNotEvaluated, schema.AttachCoverageEmpty:
		return false
	}
	_, full := attachSummary(t.Validation)
	return !full
}

func unexercisedKinds(v *schema.Validation) string {
	counts := map[string]int{}
	for i := range v.AttachPrograms {
		if p := &v.AttachPrograms[i]; p.Outcome == schema.AttachOutcomeNotAttachable {
			kind := p.Section
			if slash := strings.IndexByte(kind, '/'); slash >= 0 {
				kind = kind[:slash+1]
			}
			counts[kind]++
		}
	}
	if len(counts) == 0 {
		return "not in per-program records"
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s x%d", k, counts[k]))
	}
	return strings.Join(parts, ", ")
}
