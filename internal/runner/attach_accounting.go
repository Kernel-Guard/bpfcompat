package runner

import (
	"fmt"
	"sort"
	"strings"
	"syscall"

	"github.com/kernel-guard/bpfcompat/internal/classifier"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Bounds on the attach accounting a validator result may carry. The validator
// writes one record per program up to MAX_PROGRAM_RECORDS (1024; validators
// before v0.5 wrote at most 64), with fixed-size fields; anything beyond
// these limits did not come from it and is rejected rather than trimmed.
const (
	maxAttachRecords     = 1024
	maxAttachNameBytes   = 256
	maxAttachDetailBytes = 512
	maxAttachCount       = 1 << 20
)

// Classification codes for attach coverage that could not be established.
// None of them is a statement that the user's program failed to attach.
const (
	codeAttachNotExercised           = "ATTACH_NOT_EXERCISED"
	codeAttachScopeEmpty             = "ATTACH_SCOPE_EMPTY"
	codeAttachAccountingUnavailable  = "ATTACH_ACCOUNTING_UNAVAILABLE"
	codeAttachAccountingInconsistent = "ATTACH_ACCOUNTING_INCONSISTENT"
)

// attachAccounting is the validated view of the validator's attach record.
type attachAccounting struct {
	state         string // schema.AttachAccounting*
	problem       string // why the record was rejected, when inconsistent
	effectiveMode string
	programCount  int
	records       int
	selected      int
	notSelected   int
	attachable    int
	notAttachable int
	attempted     int
	passed        int
	failed        int
	programs      []schema.AttachProgram
}

func (a attachAccounting) truncated() bool {
	return a.state == schema.AttachAccountingV1 && a.records < a.programCount
}

// accountAttach validates the validator's attach accounting. It never repairs
// a record: anything that does not add up is "inconsistent" and none of its
// per-program detail is carried forward.
func accountAttach(vr validatorResult, requestedMode string) attachAccounting {
	at := vr.Attach
	acc := attachAccounting{attempted: at.Attempted, passed: at.Passed, failed: at.Failed}
	if strings.TrimSpace(at.Accounting) == "" {
		acc.state = schema.AttachAccountingUnavailable
		return acc
	}
	reject := func(format string, args ...any) attachAccounting {
		return attachAccounting{
			state:     schema.AttachAccountingInconsistent,
			problem:   fmt.Sprintf(format, args...),
			attempted: at.Attempted, passed: at.Passed, failed: at.Failed,
		}
	}
	if at.Accounting != schema.AttachAccountingV1 {
		return reject("unknown attach accounting version %q", truncateBytes(at.Accounting, 32))
	}
	counts := []struct {
		name string
		v    *int
	}{
		{"program_count", at.ProgramCount}, {"records", at.Records}, {"selected", at.Selected},
		{"not_selected", at.NotSelected}, {"attachable", at.Attachable}, {"not_attachable", at.NotAttachable},
	}
	for _, c := range counts {
		if c.v == nil {
			return reject("attach.%s is missing", c.name)
		}
		if *c.v < 0 || *c.v > maxAttachCount {
			return reject("attach.%s=%d is out of range", c.name, *c.v)
		}
	}
	for _, c := range []struct {
		name string
		v    int
	}{{"attempted", at.Attempted}, {"passed", at.Passed}, {"failed", at.Failed}} {
		if c.v < 0 || c.v > maxAttachCount {
			return reject("attach.%s=%d is out of range", c.name, c.v)
		}
	}
	acc.state = schema.AttachAccountingV1
	acc.effectiveMode = at.EffectiveMode
	acc.programCount, acc.records = *at.ProgramCount, *at.Records
	acc.selected, acc.notSelected = *at.Selected, *at.NotSelected
	acc.attachable, acc.notAttachable = *at.Attachable, *at.NotAttachable

	switch acc.effectiveMode {
	case "disabled", "best-effort", "required":
	default:
		return reject("unknown effective attach mode %q", truncateBytes(acc.effectiveMode, 32))
	}
	if requested := strings.TrimSpace(requestedMode); requested != "" && requested != acc.effectiveMode {
		return reject("validator ran attach mode %q but %q was requested", acc.effectiveMode, requested)
	}
	switch {
	case acc.attempted != acc.passed+acc.failed:
		return reject("attempted=%d != passed=%d + failed=%d", acc.attempted, acc.passed, acc.failed)
	case acc.selected+acc.notSelected != acc.programCount:
		return reject("selected=%d + not_selected=%d != program_count=%d", acc.selected, acc.notSelected, acc.programCount)
	case acc.attachable+acc.notAttachable != acc.selected:
		return reject("attachable=%d + not_attachable=%d != selected=%d", acc.attachable, acc.notAttachable, acc.selected)
	case acc.records > acc.programCount:
		return reject("records=%d exceeds program_count=%d", acc.records, acc.programCount)
	case len(vr.Discovery.Programs) > maxAttachRecords:
		return reject("%d program records exceed the bound of %d", len(vr.Discovery.Programs), maxAttachRecords)
	case acc.records != len(vr.Discovery.Programs):
		return reject("records=%d but %d program records are present", acc.records, len(vr.Discovery.Programs))
	}
	// A validator that declares its record bound stops recording only there:
	// fewer records than programs below that bound is a silent truncation.
	if b := at.RecordsBound; b != nil {
		switch {
		case *b <= 0 || *b > maxAttachRecords:
			return reject("attach.records_bound=%d is outside 1..%d", *b, maxAttachRecords)
		case acc.records < acc.programCount && acc.records != *b:
			return reject("records=%d of program_count=%d although the declared record bound is %d", acc.records, acc.programCount, *b)
		}
	}

	// The attach phase runs exactly when the object loaded and attach is not
	// disabled, and then tries every attachable program. The status the
	// validator reports is a function of the counts; a record whose status
	// disagrees with them (a "pass" next to a failed attach) is rejected, so
	// no verdict rests on whichever of the two fields is greener.
	phaseRan := vr.Load.Status == "pass" && acc.effectiveMode != "disabled"
	if phaseRan && acc.attempted != acc.attachable {
		return reject("attempted=%d but attachable=%d; the attach phase must try every attachable program", acc.attempted, acc.attachable)
	}
	if !phaseRan && acc.attempted != 0 {
		return reject("attempted=%d although the attach phase did not run", acc.attempted)
	}
	if want := expectedAttachStatus(phaseRan, acc); at.Status != want {
		return reject("attach.status=%q but the counts imply %q", truncateBytes(at.Status, 32), want)
	}
	if at.Status == "fail" && vr.Status != "fail" {
		return reject("attach.status is fail but the overall status is %q", truncateBytes(vr.Status, 32))
	}
	seen := make(map[string]struct{}, len(vr.Discovery.Programs))
	tally := map[string]int{}
	selectedRecords := 0
	programs := make([]schema.AttachProgram, 0, len(vr.Discovery.Programs))
	for i := range vr.Discovery.Programs {
		p := &vr.Discovery.Programs[i]
		switch {
		case p.Name == "":
			return reject("program record %d has no name", i)
		case len(p.Name) > maxAttachNameBytes:
			return reject("program record %d name exceeds %d bytes", i, maxAttachNameBytes)
		case len(p.Section) > maxAttachNameBytes:
			return reject("program %q section exceeds %d bytes", p.Name, maxAttachNameBytes)
		case len(p.AttachError) > maxAttachDetailBytes:
			return reject("program %q attach detail exceeds %d bytes", p.Name, maxAttachDetailBytes)
		case len(p.AttachOperation) > 64:
			return reject("program %q attach operation is oversized", p.Name)
		case p.Autoload == nil:
			return reject("program %q has no autoload state", p.Name)
		}
		if _, dup := seen[p.Name]; dup {
			return reject("duplicate program name %q", p.Name)
		}
		seen[p.Name] = struct{}{}
		switch p.AttachOutcome {
		case schema.AttachOutcomeAttached, schema.AttachOutcomeFailed, schema.AttachOutcomeNotAttachable:
			if !*p.Autoload {
				return reject("program %q was not selected but reports outcome %q", p.Name, p.AttachOutcome)
			}
			if !phaseRan {
				return reject("program %q reports %q although the attach phase did not run", p.Name, p.AttachOutcome)
			}
		case schema.AttachOutcomeNotSelected:
			if *p.Autoload {
				return reject("program %q is selected but reports outcome %q", p.Name, p.AttachOutcome)
			}
		case schema.AttachOutcomeNotAttempted:
			if phaseRan {
				return reject("program %q reports %q although the attach phase ran", p.Name, p.AttachOutcome)
			}
		default:
			return reject("program %q has unknown attach outcome %q", p.Name, truncateBytes(p.AttachOutcome, 32))
		}
		if *p.Autoload {
			selectedRecords++
		}
		tally[p.AttachOutcome]++
		rec := schema.AttachProgram{
			Name:      p.Name,
			Section:   p.Section,
			Selected:  *p.Autoload,
			Outcome:   p.AttachOutcome,
			Operation: p.AttachOperation,
		}
		if p.AttachOutcome == schema.AttachOutcomeFailed {
			rec.Errno = p.AttachErrno
			rec.Detail = p.AttachError
			rec.ReasonClass = attachErrnoClass(p.AttachErrno)
			rec.Attribution = "errno_only"
		}
		programs = append(programs, rec)
	}

	// With every program recorded, the per-program outcomes must reproduce the
	// whole-object counts exactly. With truncated records they can only bound
	// them.
	complete := acc.records == acc.programCount
	check := func(got, want int) bool {
		if complete {
			return got == want
		}
		return got <= want
	}
	switch {
	case !check(tally[schema.AttachOutcomeAttached], acc.passed):
		return reject("per-program attached=%d disagrees with passed=%d", tally[schema.AttachOutcomeAttached], acc.passed)
	case !check(tally[schema.AttachOutcomeFailed], acc.failed):
		return reject("per-program failed=%d disagrees with failed=%d", tally[schema.AttachOutcomeFailed], acc.failed)
	case !check(tally[schema.AttachOutcomeNotSelected], acc.notSelected):
		return reject("per-program not_selected=%d disagrees with not_selected=%d", tally[schema.AttachOutcomeNotSelected], acc.notSelected)
	case phaseRan && !check(tally[schema.AttachOutcomeNotAttachable], acc.notAttachable):
		return reject("per-program not_attachable=%d disagrees with not_attachable=%d", tally[schema.AttachOutcomeNotAttachable], acc.notAttachable)
	case !check(selectedRecords, acc.selected):
		return reject("per-program selected=%d disagrees with selected=%d", selectedRecords, acc.selected)
	}
	acc.programs = programs
	return acc
}

// expectedAttachStatus is the validator's finalize_attach_status as a function
// of the accounted counts.
func expectedAttachStatus(phaseRan bool, acc attachAccounting) string {
	switch {
	case !phaseRan || acc.attempted == 0:
		return "skipped"
	case acc.failed == 0:
		return "pass"
	case acc.effectiveMode == "required":
		return "fail"
	default:
		return "warn"
	}
}

// attachCoverage is how much of the selected scope the attach phase exercised.
// It is computed from scope and attempts, never from successes.
func attachCoverage(acc attachAccounting, loadPassed bool) string {
	if acc.state != schema.AttachAccountingV1 {
		return schema.AttachCoverageUnavailable
	}
	if !loadPassed || acc.effectiveMode == "disabled" {
		return schema.AttachCoverageNotEvaluated
	}
	switch {
	case acc.selected == 0:
		return schema.AttachCoverageEmpty
	case acc.attempted == 0:
		return schema.AttachCoverageNone
	case acc.attempted < acc.selected:
		return schema.AttachCoveragePartial
	default:
		return schema.AttachCoverageComplete
	}
}

// attachErrnoClass names the errno family of a failed attach. It is a
// normalization of the raw errno, not a diagnosis: ENOENT from a kprobe attach
// may be a missing symbol, a missing tracefs, or something else entirely.
func attachErrnoClass(errno int) string {
	if errno < 0 {
		errno = -errno
	}
	switch errno {
	case 0:
		return "ERRNO_UNKNOWN"
	case int(syscall.ENOENT):
		return "ERRNO_ENOENT"
	case int(syscall.EPERM), int(syscall.EACCES):
		return "ERRNO_EPERM_EACCES"
	case int(syscall.EOPNOTSUPP), 524: // 524 = kernel-internal ENOTSUPP
		return "ERRNO_EOPNOTSUPP"
	case int(syscall.EINVAL):
		return "ERRNO_EINVAL"
	case int(syscall.EBUSY), int(syscall.EEXIST):
		return "ERRNO_EBUSY_EEXIST"
	default:
		return "ERRNO_OTHER"
	}
}

func applyAttachAccounting(v *schema.Validation, acc attachAccounting, loadPassed bool) {
	v.AttachAccounting = acc.state
	v.AttachCoverage = attachCoverage(acc, loadPassed)
	if acc.state != schema.AttachAccountingV1 {
		return
	}
	v.AttachEffectiveMode = acc.effectiveMode
	v.AttachProgramCount = acc.programCount
	v.AttachSelected = acc.selected
	v.AttachNotSelected = acc.notSelected
	v.AttachAttachable = acc.attachable
	v.AttachNotAttachable = acc.notAttachable
	v.AttachRecordsTruncated = acc.truncated()
	v.AttachPrograms = acc.programs
}

// requiredAttachGap explains why required attach coverage was not established,
// or returns "" when every selected program was attached and every
// manifest-required program is among them. It is only consulted when no
// attempted program failed: a proven failure is decided elsewhere.
func requiredAttachGap(acc attachAccounting, required []string) (code, reason string) {
	switch acc.state {
	case schema.AttachAccountingUnavailable:
		return codeAttachAccountingUnavailable,
			"Attach is required, but this validator does not account for which programs it attached, so complete attach coverage cannot be established."
	case schema.AttachAccountingInconsistent:
		return codeAttachAccountingInconsistent,
			"Attach is required, but the validator's attach accounting is inconsistent (" + acc.problem + "), so it was discarded."
	}
	if acc.selected == 0 {
		return codeAttachScopeEmpty,
			"Attach is required, but the object selects no programs to load and attach."
	}
	if acc.notAttachable > 0 {
		return codeAttachNotExercised, fmt.Sprintf(
			"Attach is required, but %d of %d selected programs are of a kind the validator cannot attach (%s), so they were loaded but never attached; %d attached.",
			acc.notAttachable, acc.selected, unexercisedSections(acc), acc.passed)
	}
	if acc.attempted < acc.selected {
		return codeAttachNotExercised, fmt.Sprintf(
			"Attach is required, but only %d of %d selected programs were attempted.", acc.attempted, acc.selected)
	}
	attached := map[string]bool{}
	for i := range acc.programs {
		p := &acc.programs[i]
		if p.Outcome == schema.AttachOutcomeAttached {
			attached[p.Name] = true
		}
	}
	var missing []string
	for _, name := range required {
		if !attached[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return codeAttachNotExercised, fmt.Sprintf(
			"Attach is required, but manifest program(s) %s were not attached: not selected for load, not present in the object, or beyond the validator's per-program records.",
			strings.Join(missing, ", "))
	}
	return "", ""
}

// unexercisedSections summarizes the sections of selected programs the
// validator could not attach, e.g. "xdp x1, lsm/ x2".
func unexercisedSections(acc attachAccounting) string {
	counts := map[string]int{}
	for i := range acc.programs {
		p := &acc.programs[i]
		if p.Outcome == schema.AttachOutcomeNotAttachable {
			counts[sectionKind(p.Section)]++
		}
	}
	if len(counts) == 0 {
		return "sections beyond the per-program records"
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

// sectionKind reduces a section to its attach kind ("kprobe/", "xdp").
func sectionKind(section string) string {
	if i := strings.IndexByte(section, '/'); i >= 0 {
		return section[:i+1]
	}
	if section == "" {
		return "(no section)"
	}
	return section
}

// attachCoverageNote is the visible marker for a target whose attach scope was
// not fully exercised or not fully attached. Empty when coverage is complete
// and nothing failed.
func attachCoverageNote(acc attachAccounting, coverage string) string {
	if acc.state != schema.AttachAccountingV1 {
		return ""
	}
	var failedNames []string
	for i := range acc.programs {
		p := &acc.programs[i]
		if p.Outcome == schema.AttachOutcomeFailed {
			failedNames = append(failedNames, p.Name)
		}
	}
	notExercised := acc.selected - acc.attempted
	if coverage == schema.AttachCoverageComplete && acc.failed == 0 {
		return ""
	}
	if coverage == schema.AttachCoverageNotEvaluated || coverage == schema.AttachCoverageEmpty {
		return ""
	}
	parts := []string{fmt.Sprintf("%d/%d selected programs attached", acc.passed, acc.selected)}
	if acc.failed > 0 {
		f := fmt.Sprintf("%d failed", acc.failed)
		if len(failedNames) > 0 {
			f += " (" + strings.Join(failedNames, ", ") + ")"
		}
		parts = append(parts, f)
	}
	if notExercised > 0 {
		parts = append(parts, fmt.Sprintf("%d not exercised (%s)", notExercised, unexercisedSections(acc)))
	}
	if acc.truncated() {
		parts = append(parts, fmt.Sprintf("per-program records cover %d of %d programs", acc.records, acc.programCount))
	}
	// "Not exercised" and "tried and failed" are different facts; the marker
	// names whichever applies.
	marker := "attach not fully attached"
	if notExercised > 0 {
		marker = "attach not fully exercised"
	}
	return marker + ": " + strings.Join(parts, ", ")
}

// attachFailuresForClassifier hands the classifier the raw per-program attach
// failures. Validated accounting carries the errno; an older validator only
// has the strerror text, so its errno is left unknown (0) rather than guessed.
func attachFailuresForClassifier(acc attachAccounting, vr validatorResult) []classifier.AttachFailure {
	var out []classifier.AttachFailure
	if acc.state == schema.AttachAccountingV1 {
		for i := range acc.programs {
			p := &acc.programs[i]
			if p.Outcome == schema.AttachOutcomeFailed {
				out = append(out, classifier.AttachFailure{Program: p.Name, Section: p.Section, Errno: p.Errno, Detail: p.Detail})
			}
		}
		return out
	}
	for i := range vr.Discovery.Programs {
		p := &vr.Discovery.Programs[i]
		if p.AttachStatus != "fail" || len(out) >= maxAttachRecords {
			continue
		}
		out = append(out, classifier.AttachFailure{
			Program: truncateBytes(p.Name, maxAttachNameBytes),
			Section: truncateBytes(p.Section, maxAttachNameBytes),
			Detail:  truncateBytes(p.AttachError, maxAttachDetailBytes),
		})
	}
	return out
}

func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
