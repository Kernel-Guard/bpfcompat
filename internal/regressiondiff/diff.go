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
	// EnvironmentEstablished is false when this side ran, but not on the
	// environment the obligation names.
	EnvironmentEstablished bool `json:"environment_established"`
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
		id := strings.TrimSpace(r.Targets[i].ProfileID)
		if id == "" {
			return &InvalidEvidenceError{Side: side, Reason: fmt.Sprintf(
				"target %d has an empty profile_id, so the obligation it represents is unidentifiable", i)}
		}
		if first, dup := seen[id]; dup {
			return &InvalidEvidenceError{Side: side, Reason: fmt.Sprintf(
				"profile_id %q appears at targets %d and %d; which result represents that obligation is ambiguous", id, first, i)}
		}
		seen[id] = i
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

func sideOf(t *schema.Target) CellSide {
	s := CellSide{
		Present:                true,
		Verdict:                t.Verdict,
		Status:                 t.Status,
		Required:               t.Required,
		ClassificationCode:     t.ClassificationCode,
		EnvironmentEstablished: schema.EstablishedRequestedEnvironment(t),
	}
	if t.Environment != nil {
		s.RequestedKernelFamily = t.Environment.RequestedKernelFamily
		s.ObservedKernel = t.Environment.ObservedKernel
		s.KernelFamilyMatch = t.Environment.KernelFamilyMatch
	}
	return s
}

// conclusive reports whether a side actually settled the obligation. Only
// COMPATIBLE and INCOMPATIBLE are answers about the software, and only when the
// environment that ran was the one the obligation names.
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
func Build(baseline, candidate schema.ReportV01, baselinePath, candidatePath, generatedAt string) (Diff, error) {
	if err := Validate(baseline, "baseline"); err != nil {
		return Diff{}, err
	}
	if err := Validate(candidate, "candidate"); err != nil {
		return Diff{}, err
	}
	d := Diff{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   generatedAt,
		Baseline:      refOf(baseline, baselinePath),
		Candidate:     refOf(candidate, candidatePath),
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

func inconclusiveReason(cell Cell) string {
	describe := func(side string, s CellSide) string {
		switch {
		case !s.Present:
			return side + " has no evidence for this environment"
		case !s.EnvironmentEstablished:
			return fmt.Sprintf("%s requested kernel family %s but ran %s, so it never tested the environment this obligation names",
				side, s.RequestedKernelFamily, s.ObservedKernel)
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
	var parts []string
	if !conclusive(cell.Baseline) {
		parts = append(parts, describe("baseline", cell.Baseline))
	}
	if !conclusive(cell.Candidate) {
		parts = append(parts, describe("candidate", cell.Candidate))
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
