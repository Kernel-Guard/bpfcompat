package regressiondiff

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// truncatedSide builds a 70-program target whose first 64 programs are
// recorded (p00..p63, attached unless overridden) and whose 6 unrecorded
// programs are described only by the whole-object counts.
func truncatedSide(tg schema.Target, recorded []ap, unrecAttached, unrecFailed int) schema.Target {
	tg = withAttach(tg, "best-effort", recorded...)
	v := tg.Validation
	v.AttachProgramCount += unrecAttached + unrecFailed
	v.AttachSelected += unrecAttached + unrecFailed
	v.AttachAttachable += unrecAttached + unrecFailed
	v.AttachAttempted += unrecAttached + unrecFailed
	v.AttachPassed += unrecAttached
	v.AttachFailed += unrecFailed
	v.AttachRecordsTruncated = true
	switch {
	case v.AttachFailed > 0:
		v.AttachStatus = "warn"
	default:
		v.AttachStatus = "pass"
	}
	return tg
}

func sixtyFour(override map[string]string) []ap {
	out := make([]ap, 0, 64)
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("p%02d", i)
		outcome := schema.AttachOutcomeAttached
		if o, ok := override[name]; ok {
			outcome = o
		}
		out = append(out, ap{name, tpSec, outcome, 0})
	}
	return out
}

func TestTruncatedSwapAmongUnrecordedProgramsIsInconclusive(t *testing.T) {
	// 66 programs, 64 recorded and identical on both sides. Of the two
	// unrecorded programs x and y, the baseline attached x and failed y; the
	// candidate failed x and attached y. Every aggregate count is identical
	// (passed=65, failed=1), so the swap -- a real attached -> failed on x --
	// is invisible in the report. Calling the cell UNCHANGED_COMPATIBLE would
	// claim a comparison the evidence cannot make.
	base := truncatedSide(compat(), sixtyFour(nil), 1, 1)
	cand := truncatedSide(compat(), sixtyFour(nil), 1, 1)
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification == UnchangedCompatible || c.Classification == Fixed {
		t.Fatalf("truncated records with unrecorded programs in more than one state compared as %s: %s", c.Classification, c.Reason)
	}
	if c.Classification != Inconclusive || !strings.Contains(c.Reason, "program identity is unknown") {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestTruncatedRecordsWithUniformUnrecordedStateStayComparable(t *testing.T) {
	// Every unrecorded program attached on both sides: no swap is possible.
	base := truncatedSide(compat(), sixtyFour(nil), 6, 0)
	cand := truncatedSide(compat(), sixtyFour(nil), 6, 0)
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != UnchangedCompatible {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestTruncationDoesNotHideAProvenRegression(t *testing.T) {
	base := truncatedSide(compat(), sixtyFour(nil), 1, 1)
	cand := truncatedSide(compat(), sixtyFour(map[string]string{"p07": schema.AttachOutcomeFailed}), 1, 1)
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != NewRegression || !strings.Contains(c.Reason, `"p07"`) {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

// --- what changed between the two sides of a regression -------------------

func regressionPair(baseSHA, candSHA, baseKernel, candKernel string) (schema.ReportV01, schema.ReportV01) {
	b := compat()
	b.Environment.ObservedKernel = baseKernel
	c := incompat()
	c.Environment.ObservedKernel = candKernel
	br, cr := report(b), report(c)
	br.Artifact.SHA256, cr.Artifact.SHA256 = baseSHA, candSHA
	return br, cr
}

func TestRegressionSaysWhichInputsChanged(t *testing.T) {
	cases := []struct {
		name                         string
		bSHA, cSHA, bKernel, cKernel string
		attribution                  string
		changed                      []string
		mustSay, mustNotSay          string
	}{
		{"A: different artifacts, same observed kernel", "aaa", "bbb", "5.15.0-186-generic", "5.15.0-186-generic",
			"artifact", []string{"artifact"}, "only the shipped program changed", "kernel changed"},
		{"B: same artifact across a kernel upgrade", "aaa", "aaa", "5.15.0-186-generic", "5.15.0-189-generic",
			"environment", []string{"kernel"}, "the shipped program is unchanged", "the artifact changed"},
		{"C: artifact and kernel both changed", "aaa", "bbb", "5.15.0-186-generic", "5.15.0-189-generic",
			"multiple", []string{"artifact", "kernel"}, "cannot be attributed", "only the shipped program changed"},
		{"neither recorded as changed", "aaa", "aaa", "5.15.0-186-generic", "5.15.0-186-generic",
			"none_recorded", nil, "neither", "only the shipped program changed"},
		{"artifact identity missing", "", "bbb", "5.15.0-186-generic", "5.15.0-186-generic",
			"unknown", nil, "cannot be determined", "only the shipped program changed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br, cr := regressionPair(tc.bSHA, tc.cSHA, tc.bKernel, tc.cKernel)
			c := onlyCell(t, build(t, br, cr))
			// A kernel-upgrade failure is the product's use case: it must stay a
			// gating regression, never be hidden.
			if c.Classification != NewRegression {
				t.Fatalf("got %s: %s", c.Classification, c.Reason)
			}
			if c.Attribution != tc.attribution || strings.Join(c.ChangedInputs, ",") != strings.Join(tc.changed, ",") {
				t.Fatalf("attribution=%q changed=%v", c.Attribution, c.ChangedInputs)
			}
			if !strings.Contains(c.Reason, tc.mustSay) || strings.Contains(c.Reason, tc.mustNotSay) {
				t.Fatalf("reason %q must say %q and not %q", c.Reason, tc.mustSay, tc.mustNotSay)
			}
		})
	}
}

func TestPerProgramAttachRegressionCarriesAttribution(t *testing.T) {
	b := withAttach(compat(), "best-effort", attached("a"))
	c := withAttach(compat(), "best-effort", failed("a"))
	c.Environment.ObservedKernel = "5.15.0-189-generic"
	br, cr := report(b), report(c)
	cell := onlyCell(t, build(t, br, cr))
	if cell.Classification != NewRegression || cell.Attribution != "environment" {
		t.Fatalf("got %s attribution=%q: %s", cell.Classification, cell.Attribution, cell.Reason)
	}
}
