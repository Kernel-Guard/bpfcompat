package regressiondiff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Exit codes, matching the process contract the rest of bpfcompat uses:
//
//	0  no new required regression, and every required comparison was established
//	1  the required comparison could not be established (never a claim about
//	   the candidate's software)
//	2  a required environment the baseline supported is broken in the candidate
const (
	ExitNoRegressions = 0
	ExitInconclusive  = 1
	ExitRegressed     = 2
)

// LoadReport reads one evidence file. A file that is absent, not valid JSON, or
// carrying anything after the report is an error rather than a partial report,
// so neither a typo in a path nor a truncated or concatenated file can be
// mistaken for "nothing regressed".
func LoadReport(path string) (schema.ReportV01, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return schema.ReportV01{}, fmt.Errorf("read report %s: %w", path, err)
	}
	var report schema.ReportV01
	dec := json.NewDecoder(bytes.NewReader(blob))
	if err := dec.Decode(&report); err != nil {
		return schema.ReportV01{}, fmt.Errorf("parse report %s: %w", path, err)
	}
	// Decode stops after one JSON value and is happy to leave the rest of the
	// file unread. Evidence with anything after the report -- a second value, a
	// truncated append, stray bytes -- is not evidence we can vouch for, and
	// comparing only its first value would look entirely successful.
	if err := requireEOF(dec); err != nil {
		return schema.ReportV01{}, fmt.Errorf("parse report %s: %w", path, err)
	}
	return report, nil
}

func requireEOF(dec *json.Decoder) error {
	var trailing json.RawMessage
	switch err := dec.Decode(&trailing); {
	case errors.Is(err, io.EOF):
		return nil
	case err != nil:
		return fmt.Errorf("unexpected data after the report: %w", err)
	default:
		return fmt.Errorf("unexpected data after the report: a second JSON value is present")
	}
}

// Compare loads both reports, validates their schemas and comparison keys, and
// builds the diff. It touches nothing but those two files: no database, no
// network, no service. Every failure here is an inability to compare, which the
// caller reports as exit 1 and never as a verdict on the candidate.
func Compare(baselinePath, candidatePath string, now time.Time) (Diff, error) {
	baseline, err := LoadReport(baselinePath)
	if err != nil {
		return Diff{}, err
	}
	candidate, err := LoadReport(candidatePath)
	if err != nil {
		return Diff{}, err
	}
	if err := CheckSchemas(baseline, candidate); err != nil {
		return Diff{}, err
	}
	return Build(baseline, candidate,
		absOrOriginal(baselinePath), absOrOriginal(candidatePath),
		now.UTC().Format(time.RFC3339))
}

// ExitCode maps the diff's overall result onto the process contract.
func ExitCode(d Diff) int {
	switch d.Summary.Result {
	case ResultRegressed:
		return ExitRegressed
	case ResultInconclusive:
		return ExitInconclusive
	default:
		return ExitNoRegressions
	}
}

func WriteJSON(outPath string, d Diff) error {
	if strings.TrimSpace(outPath) == "" {
		return nil
	}
	abs, err := filepath.Abs(outPath)
	if err != nil {
		return fmt.Errorf("resolve diff JSON path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("create diff JSON directory: %w", err)
	}
	blob, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("encode diff JSON: %w", err)
	}
	return os.WriteFile(abs, append(blob, '\n'), 0o600)
}

// WriteMarkdown renders the diff for humans. It is presentation only, derived
// entirely from the JSON above -- never a second source of truth.
func WriteMarkdown(outPath string, d Diff) error {
	if strings.TrimSpace(outPath) == "" {
		return nil
	}
	abs, err := filepath.Abs(outPath)
	if err != nil {
		return fmt.Errorf("resolve diff Markdown path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("create diff Markdown directory: %w", err)
	}
	return os.WriteFile(abs, []byte(Markdown(d)), 0o600)
}

func Markdown(d Diff) string {
	var b strings.Builder
	b.WriteString("# bpfcompat Release Regression Diff\n\n")
	b.WriteString(fmt.Sprintf("- Result: `%s`\n", d.Summary.Result))
	b.WriteString(fmt.Sprintf("- Baseline: `%s` (run `%s`)\n", d.Baseline.Path, emptyAsDash(d.Baseline.RunID)))
	b.WriteString(fmt.Sprintf("- Candidate: `%s` (run `%s`)\n", d.Candidate.Path, emptyAsDash(d.Candidate.RunID)))
	if d.Baseline.ArtifactSHA256 != "" || d.Candidate.ArtifactSHA256 != "" {
		b.WriteString(fmt.Sprintf("- Artifact: `%s` -> `%s`\n",
			shortSHA(d.Baseline.ArtifactSHA256), shortSHA(d.Candidate.ArtifactSHA256)))
	}
	b.WriteString(fmt.Sprintf("- Loader contract: `%s` -> `%s`\n", d.Baseline.LoaderMode, d.Candidate.LoaderMode))

	// Incomplete inputs are stated up front: a diff over partial evidence is a
	// weaker claim than it looks, and this is what a reader sees first.
	writeCoverage(&b, "Baseline", d.Summary.BaselineComplete)
	writeCoverage(&b, "Candidate", d.Summary.CandidateComplete)

	b.WriteString("\n## Summary\n\n")
	b.WriteString("| Outcome | Count |\n|---|---:|\n")
	for _, row := range []struct {
		label string
		n     int
	}{
		{"New required regressions", d.Summary.NewRequiredRegressions},
		{"New optional regressions (non-gating)", d.Summary.NewOptionalRegressions},
		{"Existing incompatibilities", d.Summary.ExistingIncompatibility},
		{"Fixed", d.Summary.Fixed},
		{"Unchanged compatible", d.Summary.UnchangedCompatible},
		{"Inconclusive (required)", d.Summary.InconclusiveRequired},
		{"Inconclusive (optional)", d.Summary.InconclusiveOptional},
		{"Coverage added", d.Summary.CoverageAddedCount},
		{"Coverage removed (required)", d.Summary.CoverageRemovedRequired},
		{"Coverage removed (optional)", d.Summary.CoverageRemovedOptional},
	} {
		b.WriteString(fmt.Sprintf("| %s | %d |\n", row.label, row.n))
	}

	if len(d.Notes) > 0 {
		b.WriteString("\n## Notes\n\n")
		for _, n := range d.Notes {
			b.WriteString("- " + n + "\n")
		}
	}

	if len(d.Cells) > 0 {
		b.WriteString("\n## Environments\n\n")
		b.WriteString("| Profile | Required | Baseline | Candidate | Classification | Why |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		cells := append([]Cell(nil), d.Cells...)
		sort.SliceStable(cells, func(i, j int) bool {
			return classificationRank(cells[i]) < classificationRank(cells[j])
		})
		for i := range cells {
			c := &cells[i]
			b.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s | `%s` | %s |\n",
				c.ProfileID,
				boolCell(c.Required),
				emptyAsDash(c.Baseline.Verdict),
				emptyAsDash(c.Candidate.Verdict),
				c.Classification,
				markdownCell(c.Reason),
			))
		}
	}
	return b.String()
}

func writeCoverage(b *strings.Builder, label string, complete *bool) {
	if complete == nil {
		return
	}
	if *complete {
		b.WriteString("- " + label + " coverage: `complete`\n")
		return
	}
	b.WriteString("- " + label + " coverage: `incomplete` — some environments produced no compatibility answer\n")
}

// classificationRank puts what blocks a release at the top of the table.
func classificationRank(c Cell) int {
	switch c.Classification {
	case NewRegression:
		if c.Required {
			return 0
		}
		return 1
	case CoverageRemoved, Inconclusive:
		if c.Required {
			return 2
		}
		return 4
	case ExistingIncompatibility:
		return 3
	case Fixed:
		return 5
	case CoverageAdded:
		return 6
	default:
		return 7
	}
}

func boolCell(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func emptyAsDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func shortSHA(v string) string {
	if len(v) > 12 {
		return v[:12]
	}
	return emptyAsDash(v)
}

func markdownCell(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "|", "\\|"), "\n", " ")
}

func absOrOriginal(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
