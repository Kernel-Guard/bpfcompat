package regressiondiff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Attach accounting in the differ.
//
// Two separate questions are asked of the per-program records, in this order:
//
//  1. Did a program that attached at baseline fail to attach in the candidate?
//     Both sides attempted the same bpf_program__attach on the same named
//     program; success then failure is a regression whatever the verdicts or
//     the requested policy say. Best-effort mode turns that failure into a
//     COMPATIBLE target, which is exactly how it used to disappear.
//  2. Are the two sides' attach scopes comparable at all? A program that left
//     the selected scope, one the validator could attach at baseline but not
//     in the candidate (or the reverse), a section that changed under the same
//     name, or a new program whose attach failed, means "still supported"
//     cannot be read off two COMPATIBLE verdicts.
//
// Coverage is never derived from the set of programs that succeeded.

const (
	maxDiffAttachRecords   = 256
	maxDiffAttachNameBytes = 256
	maxDiffAttachDetail    = 512
	maxListedPrograms      = 6
)

var knownAttachOutcomes = map[string]bool{
	schema.AttachOutcomeAttached:      true,
	schema.AttachOutcomeFailed:        true,
	schema.AttachOutcomeNotAttachable: true,
	schema.AttachOutcomeNotSelected:   true,
	schema.AttachOutcomeNotAttempted:  true,
}

// validateAttachAccounting rejects a target whose attach accounting does not
// agree with itself. Like a status/verdict contradiction, that is a file the
// differ cannot interpret, not evidence about the software.
func validateAttachAccounting(t *schema.Target, i int, id, side string) error {
	v := t.Validation
	if v == nil {
		return nil
	}
	bad := func(format string, args ...any) error {
		return &InvalidEvidenceError{Side: side, Reason: fmt.Sprintf("target %d (%s) attach accounting: ", i, id) + fmt.Sprintf(format, args...)}
	}
	if v.AttachAccounting != schema.AttachAccountingV1 {
		if len(v.AttachPrograms) > 0 {
			return bad("carries per-program records without attach_accounting %q", schema.AttachAccountingV1)
		}
		return nil
	}
	for _, n := range []int{v.AttachAttempted, v.AttachPassed, v.AttachFailed, v.AttachProgramCount,
		v.AttachSelected, v.AttachNotSelected, v.AttachAttachable, v.AttachNotAttachable} {
		if n < 0 {
			return bad("negative count")
		}
	}
	switch {
	case v.AttachAttempted != v.AttachPassed+v.AttachFailed:
		return bad("attempted=%d != passed=%d + failed=%d", v.AttachAttempted, v.AttachPassed, v.AttachFailed)
	case v.AttachSelected+v.AttachNotSelected != v.AttachProgramCount:
		return bad("selected + not_selected != program_count")
	case v.AttachAttachable+v.AttachNotAttachable != v.AttachSelected:
		return bad("attachable + not_attachable != selected")
	case len(v.AttachPrograms) > maxDiffAttachRecords:
		return bad("%d per-program records exceed the bound of %d", len(v.AttachPrograms), maxDiffAttachRecords)
	case len(v.AttachPrograms) > v.AttachProgramCount:
		return bad("more per-program records than programs")
	}
	// The attach-phase invariants the runner enforces on the validator's
	// record. Without them a report can keep the arithmetic and still claim
	// the phase "did not run" for a program the baseline attached.
	switch v.AttachEffectiveMode {
	case "disabled", "best-effort", "required":
	default:
		return bad("unknown attach_effective_mode %q", v.AttachEffectiveMode)
	}
	if v.AttachMode != v.AttachEffectiveMode {
		return bad("attach_mode %q differs from attach_effective_mode %q", v.AttachMode, v.AttachEffectiveMode)
	}
	// The phase invariant hangs on load_status, so load_status itself must be
	// explicit and must agree with the verdict: a COMPATIBLE target whose
	// object "did not load" would otherwise switch the invariant off.
	switch v.LoadStatus {
	case "pass", "fail":
	default:
		return bad("load_status %q must be pass or fail when attach accounting is recorded", v.LoadStatus)
	}
	if v.LoadStatus == "fail" && (strings.TrimSpace(t.Status) == "pass" || strings.TrimSpace(t.Verdict) == schema.VerdictCompatible) {
		return bad("load_status fail contradicts status %q / verdict %q", t.Status, t.Verdict)
	}
	loadPassed := v.LoadStatus == "pass"
	phaseRan := loadPassed && v.AttachEffectiveMode != "disabled"
	switch {
	case phaseRan && v.AttachAttempted != v.AttachAttachable:
		return bad("attempted=%d but attachable=%d although the attach phase ran", v.AttachAttempted, v.AttachAttachable)
	case !phaseRan && v.AttachAttempted != 0:
		return bad("attempted=%d although the attach phase did not run", v.AttachAttempted)
	}
	if want := expectedCoverage(v, loadPassed); v.AttachCoverage != want {
		return bad("attach_coverage %q but the counts imply %q", v.AttachCoverage, want)
	}
	if want := expectedStatus(v, phaseRan); v.AttachStatus != want {
		return bad("attach_status %q but the counts imply %q", v.AttachStatus, want)
	}
	seen := make(map[string]bool, len(v.AttachPrograms))
	tally := map[string]int{}
	for j := range v.AttachPrograms {
		p := &v.AttachPrograms[j]
		switch {
		case p.Name == "":
			return bad("record %d has no program name", j)
		case len(p.Name) > maxDiffAttachNameBytes || len(p.Section) > maxDiffAttachNameBytes || len(p.Detail) > maxDiffAttachDetail:
			return bad("record %d is oversized", j)
		case seen[p.Name]:
			return bad("program %q is recorded twice", p.Name)
		case !knownAttachOutcomes[p.Outcome]:
			return bad("program %q has unknown outcome %q", p.Name, p.Outcome)
		case p.Selected == (p.Outcome == schema.AttachOutcomeNotSelected):
			return bad("program %q selected=%t contradicts outcome %q", p.Name, p.Selected, p.Outcome)
		case phaseRan && p.Outcome == schema.AttachOutcomeNotAttempted:
			return bad("program %q is %q although the attach phase ran", p.Name, p.Outcome)
		case !phaseRan && (p.Outcome == schema.AttachOutcomeAttached || p.Outcome == schema.AttachOutcomeFailed ||
			p.Outcome == schema.AttachOutcomeNotAttachable):
			return bad("program %q is %q although the attach phase did not run", p.Name, p.Outcome)
		}
		seen[p.Name] = true
		tally[p.Outcome]++
	}
	complete := len(v.AttachPrograms) == v.AttachProgramCount
	within := func(got, want int) bool {
		if complete {
			return got == want
		}
		return got <= want
	}
	switch {
	case !within(tally[schema.AttachOutcomeAttached], v.AttachPassed):
		return bad("per-program attached disagrees with passed=%d", v.AttachPassed)
	case !within(tally[schema.AttachOutcomeFailed], v.AttachFailed):
		return bad("per-program failed disagrees with failed=%d", v.AttachFailed)
	case !within(tally[schema.AttachOutcomeNotSelected], v.AttachNotSelected):
		return bad("per-program not_selected disagrees with not_selected=%d", v.AttachNotSelected)
	}
	if v.AttachRecordsTruncated == complete && v.AttachProgramCount > 0 {
		return bad("attach_records_truncated=%t but %d of %d programs are recorded", v.AttachRecordsTruncated, len(v.AttachPrograms), v.AttachProgramCount)
	}
	return nil
}

// expectedCoverage recomputes attach_coverage from the counts, exactly as the
// runner derives it.
func expectedCoverage(v *schema.Validation, loadPassed bool) string {
	switch {
	case !loadPassed || v.AttachEffectiveMode == "disabled":
		return schema.AttachCoverageNotEvaluated
	case v.AttachSelected == 0:
		return schema.AttachCoverageEmpty
	case v.AttachAttempted == 0:
		return schema.AttachCoverageNone
	case v.AttachAttempted < v.AttachSelected:
		return schema.AttachCoveragePartial
	default:
		return schema.AttachCoverageComplete
	}
}

// expectedStatus is the validator's attach status as a function of the counts.
func expectedStatus(v *schema.Validation, phaseRan bool) string {
	switch {
	case !phaseRan || v.AttachAttempted == 0:
		return "skipped"
	case v.AttachFailed == 0:
		return "pass"
	case v.AttachEffectiveMode == "required":
		return "fail"
	default:
		return "warn"
	}
}

// attachSide is one side's attach evidence, as the differ reads it.
type attachSide struct {
	accounted bool // validated v1 accounting
	truncated bool
	failed    int // aggregate attach failures, with or without accounting
	programs  map[string]*schema.AttachProgram

	// Whole-object counts, compared when per-program records cannot be.
	selected, attachable, notAttachable, passed     int
	coverage                                        string
	records, programCount, failedCount, notSelected int
	phaseRan                                        bool
}

// whollyAttached reports whether every program in the object attached: all
// selected, all attachable, none failed. Only then does nothing about any
// single program need to be known to rule out a hidden change.
func (s attachSide) whollyAttached() bool {
	return s.phaseRan && s.programCount > 0 && s.passed == s.programCount
}

func describeTruncatedSide(side string, s attachSide) string {
	return fmt.Sprintf("%s records %d of %d programs (attached %d, failed %d, not attachable %d, not selected %d)",
		side, s.records, s.programCount, s.passed, s.failedCount, s.notAttachable, s.notSelected)
}

func attachSideOf(t *schema.Target) attachSide {
	if t == nil || t.Validation == nil {
		return attachSide{}
	}
	v := t.Validation
	s := attachSide{failed: v.AttachFailed}
	if s.failed == 0 && (v.AttachStatus == "warn" || v.AttachStatus == "fail") {
		// The status records a failure the counts do not; trust the evidence
		// of failure over its absence.
		s.failed = 1
	}
	if v.AttachAccounting != schema.AttachAccountingV1 {
		return s
	}
	s.accounted = true
	s.truncated = len(v.AttachPrograms) < v.AttachProgramCount
	s.selected, s.attachable, s.notAttachable = v.AttachSelected, v.AttachAttachable, v.AttachNotAttachable
	s.passed, s.coverage = v.AttachPassed, v.AttachCoverage
	s.records, s.programCount = len(v.AttachPrograms), v.AttachProgramCount
	s.failedCount, s.notSelected = v.AttachFailed, v.AttachNotSelected
	s.phaseRan = v.LoadStatus == "pass" && v.AttachEffectiveMode != "disabled"
	s.programs = make(map[string]*schema.AttachProgram, len(v.AttachPrograms))
	for i := range v.AttachPrograms {
		s.programs[v.AttachPrograms[i].Name] = &v.AttachPrograms[i]
	}
	return s
}

// attachRegression reports programs attempted on both sides that attached at
// baseline and failed in the candidate. Both sides must carry validated
// accounting; the caller establishes that both environments are the ones the
// obligation names.
func attachRegression(b, c attachSide) (string, bool) {
	if !b.accounted || !c.accounted {
		return "", false
	}
	var names []string
	for name, cp := range c.programs {
		bp, ok := b.programs[name]
		if !ok || bp.Section != cp.Section {
			continue
		}
		if bp.Outcome == schema.AttachOutcomeAttached && cp.Outcome == schema.AttachOutcomeFailed {
			detail := fmt.Sprintf("%q", name)
			if cp.Errno != 0 {
				detail += fmt.Sprintf(" (errno %d)", cp.Errno)
			}
			names = append(names, detail)
		}
	}
	if len(names) == 0 {
		return "", false
	}
	sort.Strings(names)
	return fmt.Sprintf("program(s) %s attached at baseline and failed to attach in the candidate",
		listNames(names)), true
}

// attachComparability explains why the two sides' attach evidence does not
// support reading two COMPATIBLE verdicts as "attach still supported", or
// returns "" when it does. Removed programs never make a cell inconclusive on
// their own; they are reported through removedPrograms.
func attachComparability(b, c attachSide) string {
	if !b.accounted || !c.accounted {
		// Losing the accounting and attaching less are indistinguishable from
		// here, so a candidate without it cannot inherit a baseline that has
		// it -- the same rule validationDepthChanged applies to the mode.
		if b.accounted && !c.accounted {
			return "the baseline records per-program attach accounting and the candidate does not, so the candidate cannot be shown to attach what the baseline did"
		}
		if c.failed > 0 {
			missing := "the baseline does not record"
			if !c.accounted {
				missing = "neither side records"
			}
			return fmt.Sprintf("the candidate reports %d attach failure(s), but %s per-program attach accounting, so whether any of them is a regression cannot be determined",
				c.failed, missing)
		}
		return ""
	}
	var scope, capability, section, added, untried []string
	for name, cp := range c.programs {
		bp, ok := b.programs[name]
		if !ok {
			if cp.Outcome == schema.AttachOutcomeFailed {
				added = append(added, fmt.Sprintf("%q", name))
			}
			continue
		}
		switch {
		case bp.Section != cp.Section:
			section = append(section, fmt.Sprintf("%q", name))
		case bp.Selected != cp.Selected:
			scope = append(scope, fmt.Sprintf("%q", name))
		case bp.Outcome == schema.AttachOutcomeAttached && cp.Outcome == schema.AttachOutcomeNotAttempted:
			// Attached at baseline, never tried in the candidate: whatever
			// the reason, the candidate did not show it still attaches.
			untried = append(untried, fmt.Sprintf("%q", name))
		case bp.Outcome == schema.AttachOutcomeNotAttempted || cp.Outcome == schema.AttachOutcomeNotAttempted:
			// Capability unknown on one side.
		case (bp.Outcome == schema.AttachOutcomeNotAttachable) != (cp.Outcome == schema.AttachOutcomeNotAttachable):
			capability = append(capability, fmt.Sprintf("%q", name))
		}
	}
	var parts []string
	if len(scope) > 0 {
		sort.Strings(scope)
		parts = append(parts, "attach scope changed: "+listNames(scope)+" moved in or out of the selected programs")
	}
	if len(capability) > 0 {
		sort.Strings(capability)
		parts = append(parts, "validator attach capability changed for "+listNames(capability))
	}
	if len(section) > 0 {
		sort.Strings(section)
		parts = append(parts, "section changed under the same program name for "+listNames(section))
	}
	if len(untried) > 0 {
		sort.Strings(untried)
		parts = append(parts, listNames(untried)+" attached at baseline and was not attempted in the candidate")
	}
	if b.passed > 0 && (c.coverage == schema.AttachCoverageEmpty || c.coverage == schema.AttachCoverageNone) {
		parts = append(parts, fmt.Sprintf("the candidate attached nothing (attach_coverage %q) where the baseline attached %d program(s)", c.coverage, b.passed))
	}
	if len(added) > 0 {
		sort.Strings(added)
		parts = append(parts, "the candidate adds "+listNames(added)+", whose attach failed, with no baseline to compare")
	}
	if (b.truncated || c.truncated) && b.phaseRan && c.phaseRan && (!b.whollyAttached() || !c.whollyAttached()) {
		// Beyond the 64 per-program records a program has no identity: it
		// can be a different program on each side, swap state with another,
		// or move across the record boundary when programs are added or
		// removed earlier in the object, all with every count unchanged. No
		// per-program comparison can be shown from such records unless there
		// is nothing to compare -- every program on both sides attached. A
		// side whose attach phase did not run makes no attach claim and is
		// left to the mode and verdict rules.
		parts = append(parts, "per-program records are truncated ("+
			describeTruncatedSide("baseline", b)+"; "+describeTruncatedSide("candidate", c)+
			"); beyond the records program identity is unknown, so per-program comparability holds only when every program on both sides attached, which it did not")
	}
	if len(parts) == 0 {
		return ""
	}
	return "the attach evidence is not like-for-like: " + strings.Join(parts, "; ")
}

// removedPrograms lists baseline programs the candidate no longer contains.
func removedPrograms(b, c attachSide) string {
	if !b.accounted || !c.accounted || b.truncated || c.truncated {
		return ""
	}
	var gone []string
	for name := range b.programs {
		if _, ok := c.programs[name]; !ok {
			gone = append(gone, fmt.Sprintf("%q", name))
		}
	}
	if len(gone) == 0 {
		return ""
	}
	sort.Strings(gone)
	return "; program(s) " + listNames(gone) + " are no longer in the candidate"
}

func listNames(names []string) string {
	if len(names) > maxListedPrograms {
		return strings.Join(names[:maxListedPrograms], ", ") + fmt.Sprintf(" and %d more", len(names)-maxListedPrograms)
	}
	return strings.Join(names, ", ")
}
