package regressiondiff

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Counterexamples from the focused review of the truncation and attribution
// corrections.

// keepRecords builds accounting from every program, then keeps only the
// first keep per-program records, as a validator with a record cap would.
func keepRecords(tg schema.Target, mode string, keep int, progs ...ap) schema.Target {
	tg = withAttach(tg, mode, progs...)
	if keep < len(progs) {
		tg.Validation.AttachPrograms = tg.Validation.AttachPrograms[:keep]
		tg.Validation.AttachRecordsTruncated = true
	}
	return tg
}

func notAttachable(n string) ap { return ap{n, tpSec, schema.AttachOutcomeNotAttachable, 0} }
func notSelected(n string) ap   { return ap{n, tpSec, schema.AttachOutcomeNotSelected, 0} }

func attachedN(prefix string, n int) []ap {
	out := make([]ap, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, attached(fmt.Sprintf("%s%02d", prefix, i)))
	}
	return out
}

func TestTruncationAcrossTheRecordBoundaryIsInconclusive(t *testing.T) {
	green := map[string]bool{UnchangedCompatible: true, Fixed: true}
	cases := map[string][2][]ap{
		// q attached (unrecorded at baseline) -> not_attachable (recorded in a
		// complete candidate); scope counts kept equal by other changes.
		"one side complete, attached -> not_attachable": {
			append(attachedN("p", 61), notAttachable("r"), notSelected("s1"), notSelected("s2"), attached("q"), attached("w")),
			append(attachedN("p", 61), notAttachable("q"), attached("w"), attached("n")),
		},
		// q and r swap places across index 63; counts identical.
		"identity shift across the boundary": {
			append(attachedN("p", 63), notAttachable("r"), attached("q"), attached("z")),
			append(attachedN("p", 63), notAttachable("q"), attached("r"), attached("z")),
		},
		// q attached (unrecorded) -> not_selected (recorded).
		"attached -> not_selected across the boundary": {
			append(attachedN("p", 62), notSelected("s1"), notSelected("s2"), attached("q"), attached("w")),
			append(attachedN("p", 62), notSelected("q"), attached("w"), attached("n")),
		},
	}
	for name, sides := range cases {
		t.Run(name, func(t *testing.T) {
			base := keepRecords(compat(), "best-effort", 64, sides[0]...)
			cand := keepRecords(compat(), "best-effort", 64, sides[1]...)
			c := onlyCell(t, build(t, report(base), report(cand)))
			if green[c.Classification] {
				t.Fatalf("compared as %s: %s", c.Classification, c.Reason)
			}
			if c.Classification != Inconclusive || !strings.Contains(c.Reason, "program identity is unknown") {
				t.Fatalf("got %s: %s", c.Classification, c.Reason)
			}
		})
	}
}

func TestTruncatedIdenticalEvidenceWithMixedStatesIsInconclusive(t *testing.T) {
	// The documented cost of the conservative rule: identical evidence for a
	// >64-program object with a non-attached program cannot be shown
	// comparable per program. Recording every program (see #247) removes it.
	progs := append(attachedN("p", 64), attached("x"), notAttachable("y"))
	base := keepRecords(compat(), "best-effort", 64, progs...)
	cand := keepRecords(compat(), "best-effort", 64, progs...)
	if c := onlyCell(t, build(t, report(base), report(cand))); c.Classification != Inconclusive {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestTruncationWithAttachDisabledMakesNoAttachClaim(t *testing.T) {
	mk := func() schema.Target {
		tg := compat()
		v := &schema.Validation{LoadStatus: "pass", AttachMode: "disabled", AttachEffectiveMode: "disabled",
			AttachAccounting: schema.AttachAccountingV1, AttachProgramCount: 70, AttachSelected: 68, AttachNotSelected: 2,
			AttachAttachable: 68, AttachCoverage: schema.AttachCoverageNotEvaluated, AttachStatus: "skipped", AttachRecordsTruncated: true}
		for i := 0; i < 64; i++ {
			v.AttachPrograms = append(v.AttachPrograms, schema.AttachProgram{Name: fmt.Sprintf("p%02d", i), Section: tpSec, Outcome: schema.AttachOutcomeNotAttempted, Selected: true})
		}
		tg.Validation = v
		return tg
	}
	if c := onlyCell(t, build(t, report(mk()), report(mk()))); c.Classification != UnchangedCompatible {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestProvenRegressionSurvivesMixedTruncation(t *testing.T) {
	bp := append(attachedN("p", 64), attached("x"), notAttachable("y"))
	cp := append(attachedN("p", 64), attached("x"), notAttachable("y"))
	cp[3] = failed("p03")
	base := keepRecords(compat(), "best-effort", 64, bp...)
	cand := keepRecords(compat(), "best-effort", 64, cp...)
	if c := onlyCell(t, build(t, report(base), report(cand))); c.Classification != NewRegression {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestFixedCellsAreNotWordedAsRegressions(t *testing.T) {
	b := incompat()
	c := compat()
	c.Environment.ObservedKernel = "5.15.0-189-generic"
	cell := onlyCell(t, build(t, report(b), report(c)))
	if cell.Classification != Fixed || cell.Attribution != AttributionEnvironment {
		t.Fatalf("got %s/%s", cell.Classification, cell.Attribution)
	}
	if strings.Contains(cell.Reason, "regressed") {
		t.Fatalf("a fix is described as a regression: %s", cell.Reason)
	}
}

func TestCommandModeLoaderIsItsOwnInput(t *testing.T) {
	cmd := func(loader string) *schema.CommandInfo {
		ci := &schema.CommandInfo{InvocationSHA256: "i"}
		if loader != "" {
			ci.Binary = &schema.BinaryIdentity{SHA256: loader}
		}
		return ci
	}
	t.Run("loader missing on one side is unknown", func(t *testing.T) {
		br, cr := report(compat()), report(incompat())
		br.Command, cr.Command = cmd("L1"), cmd("")
		cell := onlyCell(t, build(t, br, cr))
		if cell.Attribution != AttributionUnknown {
			t.Fatalf("got %s: %s", cell.Attribution, cell.Reason)
		}
	})
	t.Run("loader changed, artifact same", func(t *testing.T) {
		br, cr := report(compat()), report(incompat())
		br.Command, cr.Command = cmd("L1"), cmd("L2")
		cell := onlyCell(t, build(t, br, cr))
		if cell.Attribution != AttributionArtifact || strings.Join(cell.ChangedInputs, ",") != "loader" ||
			!strings.Contains(cell.Reason, "loader") {
			t.Fatalf("got %s %v: %s", cell.Attribution, cell.ChangedInputs, cell.Reason)
		}
	})
}

func TestMultipleWordingDoesNotNameAnUnchangedArtifact(t *testing.T) {
	b, c := compat(), incompat()
	c.Environment.ObservedKernel = "5.15.0-189-generic"
	br, cr := report(b), report(c)
	br.Validator = &schema.BinaryIdentity{SHA256: "v1"}
	cr.Validator = &schema.BinaryIdentity{SHA256: "v2"}
	cell := onlyCell(t, build(t, br, cr))
	if cell.Attribution != AttributionMultiple || strings.Contains(cell.Reason, "artifact alone") {
		t.Fatalf("got %s: %s", cell.Attribution, cell.Reason)
	}
}
