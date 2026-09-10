// Package regressiondiff compares two bpfcompat evidence reports and reports
// how the compatibility evidence changed between them.
//
// It answers exactly one question: "did this candidate break an environment my
// baseline supported?" It is not a second compatibility classifier. It never
// re-reads validator logs, never re-runs anything, and never infers a verdict
// of its own -- it consumes the structured verdict, environment and
// completeness fields the run itself recorded.
//
// The separate internal/compare package predates the Gate 1 verdict contract
// and ranks statuses ordinally (pass 3 > fail 2 > infra_error 1). That makes a
// VM which failed to boot read as a regression, and makes a genuine
// incompatibility appearing where there was an infra error read as an
// improvement. It is still used by the frozen experimental API and is left
// alone; nothing here builds on it.
package regressiondiff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// SchemaVersion identifies the diff evidence format. Deliberately distinct from
// the run-report schema: the semantics are different, so reusing v0.1 would let
// a consumer parse one as the other.
const SchemaVersion = "bpfcompat.regression-diff.v0.1"

// supportedReportSchema is the only run-report schema this differ understands.
// Comparing structures whose semantics are unknown is worse than refusing.
const supportedReportSchema = "v0.1"

// Cell classifications. Kept deliberately small: each state exists because a
// release decision differs for it.
const (
	// UnchangedCompatible: supported before, supported now.
	UnchangedCompatible = "UNCHANGED_COMPATIBLE"

	// NewRegression: the baseline proved this environment worked and the
	// candidate proves it no longer does. The primary product signal, and the
	// only classification that is a statement about the candidate's software.
	NewRegression = "NEW_REGRESSION"

	// ExistingIncompatibility: broken before, broken now. A known limitation --
	// it must stay visible, but shipping it again is not a new regression.
	ExistingIncompatibility = "EXISTING_INCOMPATIBILITY"

	// Fixed: broken before, working now.
	Fixed = "FIXED"

	// Inconclusive: at least one side never established the compatibility of
	// this obligation, so the change cannot be known. Never upgraded to
	// NewRegression on suspicion.
	Inconclusive = "INCONCLUSIVE"

	// CoverageAdded: the candidate tests an obligation the baseline did not.
	// New evidence, not a regression.
	CoverageAdded = "COVERAGE_ADDED"

	// CoverageRemoved: the baseline tested an obligation the candidate does
	// not. Continued support cannot be established -- which is not the same as
	// the software being broken.
	CoverageRemoved = "COVERAGE_REMOVED"
)

// Overall results, mapped to exit codes by the caller.
const (
	ResultNoRegressions = "NO_NEW_REGRESSIONS"
	ResultRegressed     = "NEW_REGRESSIONS"
	ResultInconclusive  = "INCONCLUSIVE"
)

type ReportRef struct {
	Path          string `json:"path"`
	RunID         string `json:"run_id,omitempty"`
	SchemaVersion string `json:"schema_version,omitempty"`
	Verdict       string `json:"verdict,omitempty"`
	Complete      *bool  `json:"complete,omitempty"`
	// ArtifactSHA256 and the OCI fields are traceability only. They are
	// deliberately NOT part of the comparison key: release N and N+1 are
	// supposed to contain different artifacts.
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
	ArtifactSource string `json:"artifact_source,omitempty"`
	ArtifactDigest string `json:"artifact_source_digest,omitempty"`
	LoaderMode     string `json:"loader_mode,omitempty"`
	LoaderSHA256   string `json:"loader_sha256,omitempty"`
}

// CellSide is one side's evidence for a single obligation.
type CellSide struct {
	Present               bool   `json:"present"`
	Verdict               string `json:"verdict,omitempty"`
	Status                string `json:"status,omitempty"`
	Required              bool   `json:"required,omitempty"`
	ClassificationCode    string `json:"classification_code,omitempty"`
	RequestedKernelFamily string `json:"requested_kernel_family,omitempty"`
	ObservedKernel        string `json:"observed_kernel,omitempty"`
	KernelFamilyMatch     *bool  `json:"kernel_family_match,omitempty"`
	// EnvironmentEstablished is false unless this side positively recorded that
	// it ran on the environment the obligation names.
	EnvironmentEstablished bool `json:"environment_established"`
	// EnvironmentEvidence separates the two ways that can fail: "unknown" (the
	// report never said what booted) and "mismatch" (it said, and it was the
	// wrong kernel series). They are not the same finding and must not read as
	// though they were.
	EnvironmentEvidence string `json:"environment_evidence,omitempty"`
	// The requested obligation identity, recorded so a comparison that refused
	// to treat two sides as the same promise can show why.
	ProfileArch         string `json:"profile_arch,omitempty"`
	ProfileDistro       string `json:"profile_distro,omitempty"`
	ProfileVersion      string `json:"profile_version,omitempty"`
	ProfileKernelFamily string `json:"profile_kernel_family,omitempty"`
	// AttachMode is how much of the contract was exercised: load-only evidence
	// does not support a claim that attaching still works.
	AttachMode string `json:"attach_mode,omitempty"`
}

type Cell struct {
	Key             string   `json:"key"`
	ProfileID       string   `json:"profile_id"`
	Required        bool     `json:"required"`
	RequiredChanged bool     `json:"required_changed,omitempty"`
	Classification  string   `json:"classification"`
	Reason          string   `json:"reason"`
	Baseline        CellSide `json:"baseline"`
	Candidate       CellSide `json:"candidate"`
}

type Summary struct {
	TotalCells              int `json:"total_cells"`
	NewRequiredRegressions  int `json:"new_required_regressions"`
	NewOptionalRegressions  int `json:"new_optional_regressions"`
	ExistingIncompatibility int `json:"existing_incompatibilities"`
	Fixed                   int `json:"fixed"`
	UnchangedCompatible     int `json:"unchanged_compatible"`
	InconclusiveRequired    int `json:"inconclusive_required"`
	InconclusiveOptional    int `json:"inconclusive_optional"`
	CoverageAddedCount      int `json:"coverage_added"`
	CoverageRemovedRequired int `json:"coverage_removed_required"`
	CoverageRemovedOptional int `json:"coverage_removed_optional"`
	// BaselineComplete/CandidateComplete surface Gate 1's run-level coverage
	// flag, so an incomplete input cannot be read as a full comparison.
	BaselineComplete  *bool  `json:"baseline_complete,omitempty"`
	CandidateComplete *bool  `json:"candidate_complete,omitempty"`
	Result            string `json:"result"`
}

type Diff struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   string    `json:"generated_at"`
	Baseline      ReportRef `json:"baseline"`
	Candidate     ReportRef `json:"candidate"`
	Summary       Summary   `json:"summary"`
	Cells         []Cell    `json:"cells"`
	Notes         []string  `json:"notes,omitempty"`
}

// InvalidEvidenceError is returned when a report cannot supply trustworthy
// comparison keys. Every case here is an inability to compare, never a verdict
// on the candidate, so the caller maps it to exit 1.
type InvalidEvidenceError struct {
	Side, Reason string
}

func (e *InvalidEvidenceError) Error() string {
	return fmt.Sprintf("%s report cannot be compared: %s", e.Side, e.Reason)
}

// Validate rejects evidence whose comparison keys cannot be trusted.
//
// Each of these was previously tolerated, and each let a diff look conclusive
// when it was not: a report with no targets compared cleanly against anything,
// a blank profile_id silently vanished from the comparison, and a duplicated
// profile_id had its first occurrence silently chosen as the winner. Ambiguity
// about *which* obligation a cell represents is not something a release gate
// may resolve by guessing.
func Validate(r schema.ReportV01, side string) error {
	if len(r.Targets) == 0 {
		return &InvalidEvidenceError{Side: side, Reason: "it contains no targets, so it establishes nothing to compare"}
	}
	seen := make(map[string]int, len(r.Targets))
	for i := range r.Targets {
		t := &r.Targets[i]
		id := strings.TrimSpace(t.ProfileID)
		if id == "" {
			return &InvalidEvidenceError{Side: side, Reason: fmt.Sprintf(
				"target %d has an empty profile_id, so the obligation it represents is unidentifiable", i)}
		}
		if first, dup := seen[id]; dup {
			return &InvalidEvidenceError{Side: side, Reason: fmt.Sprintf(
				"profile_id %q appears at targets %d and %d; which result represents that obligation is ambiguous", id, first, i)}
		}
		seen[id] = i
		if err := validateTarget(t, i, id, side); err != nil {
			return err
		}
	}
	return validateSummary(r, side)
}

// validateTarget rejects a target that contradicts itself.
//
// A report does not become conclusive because one of its fields contains the
// word COMPATIBLE. `status` and `verdict` are two recordings of one execution:
// the runner derives the second from the first with schema.VerdictForStatus, so
// for genuine evidence they agree by construction. When they disagree, the file
// was edited or written by a producer whose semantics we do not know, and the
// honest answer is that we cannot compare it -- not that we should pick the
// field we like. Refusing is also strictly better than resolving the conflict
// as INCOMPATIBLE, which would blame a candidate for a broken input file.
func validateTarget(t *schema.Target, i int, id, side string) error {
	status := strings.TrimSpace(t.Status)
	verdict := strings.TrimSpace(t.Verdict)
	// Absence is not contradiction. A pre-Gate-1 report records status and no
	// verdict; it is unusable as a compatibility claim (conclusive() refuses
	// it) but it is not self-contradictory, and rejecting the whole file would
	// confuse "old" with "tampered with".
	if status != "" && verdict != "" && schema.VerdictForStatus(status) != verdict {
		return &InvalidEvidenceError{Side: side, Reason: fmt.Sprintf(
			"target %d (%s) records status %q and verdict %q, which contradict each other (status %q means %q); this report does not agree with itself",
			i, id, status, verdict, status, schema.VerdictForStatus(status))}
	}
	// kernel_family_match is a claim derived from two other fields: the runner
	// sets it only after parsing a kernel series out of both the requested
	// family and the observed kernel. A `true` standing alone, with nothing it
	// could have been derived from, is an assertion rather than evidence.
	if env := t.Environment; env != nil && env.KernelFamilyMatch != nil {
		if strings.TrimSpace(env.RequestedKernelFamily) == "" || strings.TrimSpace(env.ObservedKernel) == "" {
			return &InvalidEvidenceError{Side: side, Reason: fmt.Sprintf(
				"target %d (%s) states kernel_family_match without recording both the requested kernel family and the observed kernel, so the claim rests on nothing",
				i, id)}
		}
	}
	return nil
}

// validateSummary rejects a report whose run-level summary contradicts its own
// targets.
//
// The targets are the single source of semantic truth: they are what the
// comparison reads, and the summary is derived from them. Rather than choosing
// which to believe -- or carrying a contradiction forward as if it were
// trustworthy -- a report that disagrees with itself is refused.
//
// These checks deliberately use the lenient package-level helpers, because they
// reproduce the producer's own computation. Gate 2's stricter reading of
// missing environment evidence (see establishedEnvironment) applies to what the
// comparison may conclude, never to whether the producer's arithmetic was
// self-consistent; using the strict rule here would flag correct reports as
// forged.
func validateSummary(r schema.ReportV01, side string) error {
	status := strings.TrimSpace(r.Summary.Status)
	verdict := strings.TrimSpace(r.Summary.Verdict)
	if status != "" && verdict != "" && schema.VerdictForStatus(status) != verdict {
		return &InvalidEvidenceError{Side: side, Reason: fmt.Sprintf(
			"summary.status is %q and summary.verdict is %q, which contradict each other; this report does not agree with itself", status, verdict)}
	}
	if got := strings.TrimSpace(r.Summary.Verdict); got != "" {
		if want := schema.RunVerdict(r.Targets); got != want {
			return &InvalidEvidenceError{Side: side, Reason: fmt.Sprintf(
				"summary.verdict is %q but its own required targets add up to %q; this report does not agree with itself", got, want)}
		}
	}
	if r.Summary.Complete != nil {
		if want := schema.RunComplete(r.Targets); *r.Summary.Complete != want {
			return &InvalidEvidenceError{Side: side, Reason: fmt.Sprintf(
				"summary.complete is %t but its own targets add up to %t; this report does not agree with itself", *r.Summary.Complete, want)}
		}
	}
	return nil
}

// UnsupportedSchemaError is returned when a report's schema is not one this
// differ understands. Comparing it anyway would guess at semantics.
type UnsupportedSchemaError struct {
	Side, Got, Want string
}

func (e *UnsupportedSchemaError) Error() string {
	return fmt.Sprintf("%s report schema_version %q is not supported (this differ understands %q); refusing to compare structures whose semantics are unknown",
		e.Side, e.Got, e.Want)
}

// CheckSchemas fails closed on anything this differ does not understand.
func CheckSchemas(baseline, candidate schema.ReportV01) error {
	for _, s := range []struct {
		side string
		got  string
	}{{"baseline", baseline.SchemaVersion}, {"candidate", candidate.SchemaVersion}} {
		if strings.TrimSpace(s.got) != supportedReportSchema {
			return &UnsupportedSchemaError{Side: s.side, Got: s.got, Want: supportedReportSchema}
		}
	}
	return nil
}

// loaderMode derives which loader contract produced a report. A baseline taken
// with the generic validator and a candidate driven by the project's own loader
// are not the same obligation, so the comparison says so rather than pretending.
func loaderMode(r schema.ReportV01) string {
	if r.Command != nil {
		return "command"
	}
	return "artifact"
}

// checkDistinctRuns refuses a report compared against itself.
//
// Run IDs are a UTC timestamp plus a random suffix, so two sides carrying the
// same non-empty ID are one run read twice -- the usual cause being CI wiring
// that downloads the same artifact into both paths. Such a comparison is
// trivially, permanently green: it proves a run equals itself and nothing about
// a candidate release. A gate that can be satisfied by a wiring mistake is not
// protecting anything, so this is refused with the reason rather than answered
// with exit 0. It is an inability to compare, never a claim about the
// candidate.
func checkDistinctRuns(baseline, candidate Evidence) error {
	if id := strings.TrimSpace(baseline.Report.Run.ID); id != "" && id == strings.TrimSpace(candidate.Report.Run.ID) {
		return &InvalidEvidenceError{Side: "candidate", Reason: fmt.Sprintf(
			"it is the same run as the baseline (run id %q); comparing a run with itself cannot establish anything about a candidate release", id)}
	}
	if baseline.Path != "" && baseline.Path == candidate.Path {
		return &InvalidEvidenceError{Side: "candidate", Reason: fmt.Sprintf(
			"it is the same file as the baseline (%s); a release diff needs the evidence of two runs", baseline.Path)}
	}
	return nil
}

// commandContractChanged reports whether two command-mode runs tested the same
// thing.
//
// The loader binary's SHA-256 deliberately does not appear here. In command
// mode the loader is the project's own program -- it is the thing being
// released, and requiring it to be identical between release N and N+1 would
// make every real comparison incomparable. What must hold still is the *test*:
// the command that was run (recorded as invocation_sha256, the text itself
// never being published) and the exit code that counts as success. Change
// either and a later COMPATIBLE is an answer to a different question.
func commandContractChanged(baseline, candidate schema.ReportV01) (string, bool) {
	b, c := baseline.Command, candidate.Command
	if b == nil || c == nil {
		return "", false
	}
	if strings.TrimSpace(b.InvocationSHA256) != "" && strings.TrimSpace(c.InvocationSHA256) != "" &&
		strings.TrimSpace(b.InvocationSHA256) != strings.TrimSpace(c.InvocationSHA256) {
		return "the command under test changed between reports (different invocation_sha256); every cell is inconclusive because the two runs answer different questions", true
	}
	if b.ExpectedExitCode != c.ExpectedExitCode {
		return fmt.Sprintf(
			"the command success contract changed between reports (expected exit code %d at baseline, %d in the candidate); every cell is inconclusive",
			b.ExpectedExitCode, c.ExpectedExitCode), true
	}
	return "", false
}

// validatorIdentityChanged notes -- and deliberately does not gate on -- a
// change of the generic validator's build.
//
// In artifact mode the validator is bpfcompat's own measuring instrument, and
// upgrading bpfcompat between a baseline and a candidate is ordinary. Its
// load/attach contract is stable across its versions by design; that is the
// premise the whole product rests on. Gating on SHA equality would make every
// bpfcompat upgrade report every environment as incomparable, which trains
// users to ignore the gate. What the mismatch is worth is traceability: if a
// surprising NEW_REGRESSION appears, the first question is whether the
// instrument changed, and this note puts that in the evidence rather than
// leaving it to be reconstructed.
func validatorIdentityChanged(baseline, candidate ReportRef) (string, bool) {
	if baseline.LoaderMode != "artifact" || candidate.LoaderMode != "artifact" {
		return "", false
	}
	if baseline.LoaderSHA256 == "" || candidate.LoaderSHA256 == "" || baseline.LoaderSHA256 == candidate.LoaderSHA256 {
		return "", false
	}
	return fmt.Sprintf(
		"the bpfcompat validator build differs between reports (%s -> %s); this is expected across bpfcompat upgrades and does not by itself make the comparison invalid, but it is the first thing to check if a result is surprising",
		shortSHA(baseline.LoaderSHA256), shortSHA(candidate.LoaderSHA256)), true
}

// obligationChanged reports whether the two sides of a cell describe the same
// promise. profile_id is the comparison key, but a key is only as good as the
// thing it names: the same id can be pointed at a different architecture,
// distro, release or kernel series by editing a profile, and then a candidate's
// result is an answer about an environment the baseline never tested. Every
// field here comes from the profile the matrix *requested*, never from what
// happened to boot.
//
// The artifact SHA-256 and OCI digest are excluded on purpose: release N and
// N+1 are supposed to differ there, and that is the point of the comparison.
func obligationChanged(b, c CellSide) (string, bool) {
	for _, f := range []struct {
		name, base, cand string
	}{
		{"architecture", b.ProfileArch, c.ProfileArch},
		{"distro", b.ProfileDistro, c.ProfileDistro},
		{"distro version", b.ProfileVersion, c.ProfileVersion},
		{"kernel family", b.ProfileKernelFamily, c.ProfileKernelFamily},
	} {
		base, cand := strings.TrimSpace(f.base), strings.TrimSpace(f.cand)
		// Both sides must say, or there is nothing to compare -- an absent
		// field is unknown, and unknown is handled by the environment rules
		// rather than being read as a change.
		if base == "" || cand == "" || base == cand {
			continue
		}
		return fmt.Sprintf(
			"the obligation changed: this profile names %s %s at baseline and %s in the candidate, so the two results are about different environments",
			f.name, base, cand), true
	}
	return "", false
}

// validationDepthChanged reports a cell whose two sides exercised different
// amounts of the contract. A baseline that attached its programs and a
// candidate that only loaded them are not comparable evidence: the candidate's
// COMPATIBLE says nothing about attaching, which is exactly what the baseline
// proved. This fails closed in the direction that matters -- the shallower
// candidate cannot inherit the deeper baseline's green.
func validationDepthChanged(b, c CellSide) (string, bool) {
	base, cand := strings.TrimSpace(b.AttachMode), strings.TrimSpace(c.AttachMode)
	if base == "" || cand == "" || base == cand {
		return "", false
	}
	return fmt.Sprintf(
		"the validation contract changed: attach mode %q at baseline and %q in the candidate, so the two runs exercised different amounts of the contract",
		base, cand), true
}

func refOf(r schema.ReportV01, path string) ReportRef {
	ref := ReportRef{
		Path:           path,
		RunID:          r.Run.ID,
		SchemaVersion:  r.SchemaVersion,
		Verdict:        r.Summary.Verdict,
		Complete:       r.Summary.Complete,
		ArtifactSHA256: r.Artifact.SHA256,
		ArtifactSource: r.Artifact.Source,
		ArtifactDigest: r.Artifact.SourceDigest,
		LoaderMode:     loaderMode(r),
	}
	switch {
	case r.Command != nil && r.Command.Binary != nil:
		ref.LoaderSHA256 = r.Command.Binary.SHA256
	case r.Validator != nil:
		ref.LoaderSHA256 = r.Validator.SHA256
	}
	return ref
}

// Environment evidence states, recorded per side so the JSON says which of the
// two very different reasons a cell was not established.
const (
	EnvironmentEstablishedEvidence = "established"
	EnvironmentUnknownEvidence     = "unknown"
	EnvironmentMismatchEvidence    = "mismatch"
)

// establishedEnvironment is Gate 2's reading of whether a target actually
// exercised the environment its obligation names.
//
// It is deliberately stricter than schema.EstablishedRequestedEnvironment,
// which answers true when the evidence is absent. That leniency is right for
// the Gate 1 helper: a report reader must not invent a failure out of a field
// an older bpfcompat never wrote, and RunVerdict uses it to avoid blaming a
// user's software for our missing metadata. It is not right here. A release
// gate is asked "do we positively know this candidate still supports the
// environment we promise?", and "the file does not say" is not a yes. Changing
// the shared helper would silently restate every existing consumer's contract,
// so the strictness lives here, where the stricter question is asked.
//
// Unknown is kept distinct from mismatch. A file that never recorded a kernel
// is not evidence that the wrong kernel booted, and the reason text must not
// claim it is.
func establishedEnvironment(t *schema.Target) string {
	if t.Environment == nil || t.Environment.KernelFamilyMatch == nil {
		return EnvironmentUnknownEvidence
	}
	if !*t.Environment.KernelFamilyMatch {
		return EnvironmentMismatchEvidence
	}
	return EnvironmentEstablishedEvidence
}

func sideOf(t *schema.Target) CellSide {
	evidence := establishedEnvironment(t)
	s := CellSide{
		Present:                true,
		Verdict:                t.Verdict,
		Status:                 t.Status,
		Required:               t.Required,
		ClassificationCode:     t.ClassificationCode,
		EnvironmentEvidence:    evidence,
		EnvironmentEstablished: evidence == EnvironmentEstablishedEvidence,
	}
	if t.Environment != nil {
		s.RequestedKernelFamily = t.Environment.RequestedKernelFamily
		s.ObservedKernel = t.Environment.ObservedKernel
		s.KernelFamilyMatch = t.Environment.KernelFamilyMatch
	}
	if t.Profile != nil {
		s.ProfileArch = t.Profile.Arch
		s.ProfileDistro = t.Profile.Distro
		s.ProfileVersion = t.Profile.Version
		s.ProfileKernelFamily = t.Profile.KernelFamily
	}
	if t.Validation != nil {
		s.AttachMode = t.Validation.AttachMode
	}
	return s
}

// conclusive reports whether a side actually settled the obligation. Only
// COMPATIBLE and INCOMPATIBLE are answers about the software, and only when the
// environment that ran is positively known to be the one the obligation names.
func conclusive(s CellSide) bool {
	if !s.Present || !s.EnvironmentEstablished {
		return false
	}
	return s.Verdict == schema.VerdictCompatible || s.Verdict == schema.VerdictIncompatible
}

// Build compares two reports. It performs no I/O and needs no network.
//
// It returns an error rather than a Diff whenever the inputs cannot supply
// trustworthy comparison keys, so there is no path that produces a diff from
// evidence the differ had to guess about.
func Build(baselineEv, candidateEv Evidence, generatedAt string) (Diff, error) {
	baseline, candidate := baselineEv.Report, candidateEv.Report
	// Re-checked here, not only on the load path, so that no caller can reach a
	// diff without them: these are the conditions under which the comparison
	// has meaning at all.
	if err := CheckSchemas(baseline, candidate); err != nil {
		return Diff{}, err
	}
	if err := Validate(baseline, "baseline"); err != nil {
		return Diff{}, err
	}
	if err := Validate(candidate, "candidate"); err != nil {
		return Diff{}, err
	}
	if err := baselineEv.validatePresence(); err != nil {
		return Diff{}, err
	}
	if err := candidateEv.validatePresence(); err != nil {
		return Diff{}, err
	}
	if err := checkDistinctRuns(baselineEv, candidateEv); err != nil {
		return Diff{}, err
	}
	d := Diff{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   generatedAt,
		Baseline:      refOf(baseline, baselineEv.Path),
		Candidate:     refOf(candidate, candidateEv.Path),
	}

	// A change of loader contract makes every cell incomparable rather than
	// wrong: the question "did the candidate regress" has no meaning when the
	// thing doing the loading also changed.
	loaderChanged := d.Baseline.LoaderMode != d.Candidate.LoaderMode
	if loaderChanged {
		d.Notes = append(d.Notes, fmt.Sprintf(
			"loader contract changed between reports (baseline=%s candidate=%s); every cell is inconclusive because the comparison would not be like-for-like",
			d.Baseline.LoaderMode, d.Candidate.LoaderMode))
	}
	if note, changed := commandContractChanged(baseline, candidate); changed {
		loaderChanged = true
		d.Notes = append(d.Notes, note)
	}
	if note, changed := validatorIdentityChanged(d.Baseline, d.Candidate); changed {
		d.Notes = append(d.Notes, note)
	}

	baseByID := indexTargets(baseline.Targets)
	candByID := indexTargets(candidate.Targets)

	ids := make([]string, 0, len(baseByID)+len(candByID))
	seen := map[string]bool{}
	for id := range baseByID {
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	for id := range candByID {
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	// Sorted so the diff is byte-identical regardless of the order targets
	// appear in either report.
	sort.Strings(ids)

	for _, id := range ids {
		bt, hasBase := baseByID[id]
		ct, hasCand := candByID[id]
		d.Cells = append(d.Cells, classify(id, bt, hasBase, ct, hasCand, loaderChanged))
	}

	d.Summary = summarize(d.Cells)
	d.Summary.BaselineComplete = baseline.Summary.Complete
	d.Summary.CandidateComplete = candidate.Summary.Complete
	d.Summary.Result = overallResult(d.Summary)
	return d, nil
}

// indexTargets assumes Validate has already run, so every profile_id is present
// and unique. It never drops or de-duplicates anything: a comparison key that
// cannot be trusted is rejected before this point, not quietly resolved here.
func indexTargets(targets []schema.Target) map[string]*schema.Target {
	out := make(map[string]*schema.Target, len(targets))
	for i := range targets {
		t := &targets[i]
		out[strings.TrimSpace(t.ProfileID)] = t
	}
	return out
}

func classify(id string, bt *schema.Target, hasBase bool, ct *schema.Target, hasCand, loaderChanged bool) Cell {
	cell := Cell{Key: id, ProfileID: id}
	if hasBase {
		cell.Baseline = sideOf(bt)
	}
	if hasCand {
		cell.Candidate = sideOf(ct)
	}

	// Gating follows whichever side treated the obligation as required.
	//
	// Letting the candidate alone decide was a hole: demoting a profile to
	// `required: false` in the candidate turned a regression on an environment
	// the baseline promised into a non-gating optional finding, so a release
	// could dodge the gate by editing its own matrix.
	switch {
	case hasBase && hasCand:
		cell.Required = bt.Required || ct.Required
		cell.RequiredChanged = bt.Required != ct.Required
	case hasCand:
		cell.Required = ct.Required
	case hasBase:
		cell.Required = bt.Required
	}

	switch {
	case !hasBase && !hasCand:
		cell.Classification = Inconclusive
		cell.Reason = "obligation present in neither report"
		return cell
	case !hasBase:
		// Coverage was only added if the candidate actually established
		// something. A new obligation whose run hit an infrastructure failure,
		// or never recorded which kernel it ran, has added a row and no
		// evidence -- and calling that COVERAGE_ADDED would let a required
		// obligation nothing settled pass through a green gate. It also closes
		// the reverse edit: deleting a target from the *baseline* would
		// otherwise turn an inconclusive required cell into a non-gating one.
		if !conclusive(cell.Candidate) {
			cell.Classification = Inconclusive
			cell.Reason = "candidate adds an obligation the baseline did not test, but did not establish it: " +
				describeSide("candidate", cell.Candidate)
			return cell
		}
		cell.Classification = CoverageAdded
		cell.Reason = "candidate tests an environment the baseline did not; new evidence, not a regression"
		return cell
	case !hasCand:
		cell.Classification = CoverageRemoved
		cell.Reason = "baseline tested this environment and the candidate does not; continued support cannot be established"
		return cell
	}

	if loaderChanged {
		cell.Classification = Inconclusive
		cell.Reason = "loader contract differs between the two reports"
		return cell
	}

	// A requiredness change is a change to the support contract, not to the
	// software. Whether a candidate "regressed" against a promise that did not
	// exist at baseline -- or still honours one it has since dropped -- is not
	// something this evidence can settle, in either direction. Both sides of the
	// change are treated as not-like-for-like rather than reasoning
	// asymmetrically about which direction is safe.
	if cell.RequiredChanged {
		cell.Classification = Inconclusive
		cell.Reason = fmt.Sprintf(
			"the support contract changed: this environment is required=%t at baseline and required=%t in the candidate, so the two results are not like-for-like",
			cell.Baseline.Required, cell.Candidate.Required)
		return cell
	}

	// The obligation itself must be the same one. A profile that changed which
	// kernel series it claims is a different promise wearing the same name.
	bFam := strings.TrimSpace(cell.Baseline.RequestedKernelFamily)
	cFam := strings.TrimSpace(cell.Candidate.RequestedKernelFamily)
	if bFam != "" && cFam != "" && bFam != cFam {
		cell.Classification = Inconclusive
		cell.Reason = fmt.Sprintf("the obligation changed: baseline requests kernel family %s, candidate requests %s", bFam, cFam)
		return cell
	}
	if reason, changed := obligationChanged(cell.Baseline, cell.Candidate); changed {
		cell.Classification = Inconclusive
		cell.Reason = reason
		return cell
	}
	if reason, changed := validationDepthChanged(cell.Baseline, cell.Candidate); changed {
		cell.Classification = Inconclusive
		cell.Reason = reason
		return cell
	}

	// Either side failing to settle the question ends the comparison here.
	// This is the rule that stops an incomplete baseline from manufacturing a
	// regression out of a candidate failure.
	if !conclusive(cell.Baseline) || !conclusive(cell.Candidate) {
		cell.Classification = Inconclusive
		cell.Reason = inconclusiveReason(cell)
		return cell
	}

	switch {
	case cell.Baseline.Verdict == schema.VerdictCompatible && cell.Candidate.Verdict == schema.VerdictCompatible:
		cell.Classification = UnchangedCompatible
		cell.Reason = "supported at baseline and still supported"
	case cell.Baseline.Verdict == schema.VerdictCompatible && cell.Candidate.Verdict == schema.VerdictIncompatible:
		cell.Classification = NewRegression
		cell.Reason = "the baseline proved this environment worked and the candidate proves it no longer does"
	case cell.Baseline.Verdict == schema.VerdictIncompatible && cell.Candidate.Verdict == schema.VerdictIncompatible:
		cell.Classification = ExistingIncompatibility
		cell.Reason = "incompatible at baseline and still incompatible; a known limitation, not a new regression"
	default:
		cell.Classification = Fixed
		cell.Reason = "incompatible at baseline and compatible in the candidate"
	}
	return cell
}

// describeSide says, in one clause, why one side did not settle its obligation.
func describeSide(side string, s CellSide) string {
	switch {
	case !s.Present:
		return side + " has no evidence for this environment"
	case s.EnvironmentEvidence == EnvironmentMismatchEvidence:
		return fmt.Sprintf("%s requested kernel family %s but ran %s, so it never tested the environment this obligation names",
			side, s.RequestedKernelFamily, s.ObservedKernel)
	case s.EnvironmentEvidence == EnvironmentUnknownEvidence:
		// Deliberately not phrased as a mismatch: the report does not say
		// what booted, which is a different fact from booting the wrong
		// thing, and only one of them is a finding about the environment.
		return side + " does not record which kernel it ran (no environment.kernel_family_match), so it cannot support a claim about the environment this obligation names"
	case s.Verdict == schema.VerdictInfraError:
		return side + " could not establish compatibility (infrastructure failure)"
	case s.Verdict == schema.VerdictUnsupported:
		return side + " could not execute this environment"
	case s.Verdict == "":
		return side + " records no verdict"
	default:
		return fmt.Sprintf("%s verdict %q is not a compatibility answer", side, s.Verdict)
	}
}

func inconclusiveReason(cell Cell) string {
	var parts []string
	if !conclusive(cell.Baseline) {
		parts = append(parts, describeSide("baseline", cell.Baseline))
	}
	if !conclusive(cell.Candidate) {
		parts = append(parts, describeSide("candidate", cell.Candidate))
	}
	return strings.Join(parts, "; ")
}

func summarize(cells []Cell) Summary {
	s := Summary{TotalCells: len(cells)}
	for i := range cells {
		c := &cells[i]
		switch c.Classification {
		case UnchangedCompatible:
			s.UnchangedCompatible++
		case NewRegression:
			if c.Required {
				s.NewRequiredRegressions++
			} else {
				s.NewOptionalRegressions++
			}
		case ExistingIncompatibility:
			s.ExistingIncompatibility++
		case Fixed:
			s.Fixed++
		case Inconclusive:
			if c.Required {
				s.InconclusiveRequired++
			} else {
				s.InconclusiveOptional++
			}
		case CoverageAdded:
			s.CoverageAddedCount++
		case CoverageRemoved:
			if c.Required {
				s.CoverageRemovedRequired++
			} else {
				s.CoverageRemovedOptional++
			}
		}
	}
	return s
}

// overallResult mirrors Gate 1's precedence: a proven regression is a
// definitive fact about the candidate and outranks an inability to compare
// somewhere else, so unrelated infrastructure noise cannot bury it.
func overallResult(s Summary) string {
	switch {
	case s.NewRequiredRegressions > 0:
		return ResultRegressed
	case s.InconclusiveRequired > 0 || s.CoverageRemovedRequired > 0:
		return ResultInconclusive
	default:
		return ResultNoRegressions
	}
}
