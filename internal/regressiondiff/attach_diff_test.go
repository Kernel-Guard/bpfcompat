package regressiondiff

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Attach truth in the differ: whether a program still attaches is compared
// per program, by its stable name, and never inferred from the verdict or
// from the set of programs that happened to succeed.

type ap struct {
	name, section, outcome string
	errno                  int
}

// withAttach records validated (v1) attach accounting on a target, computed
// from the per-program outcomes so every fixture is self-consistent.
func withAttach(tg schema.Target, mode string, progs ...ap) schema.Target {
	v := &schema.Validation{
		LoadStatus: "pass", AttachMode: mode, AttachEffectiveMode: mode,
		AttachAccounting: schema.AttachAccountingV1, AttachProgramCount: len(progs),
	}
	for _, p := range progs {
		rec := schema.AttachProgram{Name: p.name, Section: p.section, Outcome: p.outcome, Selected: p.outcome != schema.AttachOutcomeNotSelected}
		switch p.outcome {
		case schema.AttachOutcomeAttached:
			v.AttachPassed++
			v.AttachAttempted++
			rec.Operation = "bpf_program__attach"
		case schema.AttachOutcomeFailed:
			v.AttachFailed++
			v.AttachAttempted++
			rec.Operation = "bpf_program__attach"
			rec.Errno = p.errno
			rec.ReasonClass = "OTHER"
			rec.Attribution = "errno_only"
		case schema.AttachOutcomeNotAttachable:
			v.AttachNotAttachable++
		case schema.AttachOutcomeNotSelected:
			v.AttachNotSelected++
		}
		v.AttachPrograms = append(v.AttachPrograms, rec)
	}
	v.AttachSelected = len(progs) - v.AttachNotSelected
	v.AttachAttachable = v.AttachSelected - v.AttachNotAttachable
	switch {
	case v.AttachSelected == 0:
		v.AttachCoverage = schema.AttachCoverageEmpty
	case v.AttachAttempted == 0:
		v.AttachCoverage = schema.AttachCoverageNone
	case v.AttachAttempted < v.AttachSelected:
		v.AttachCoverage = schema.AttachCoveragePartial
	default:
		v.AttachCoverage = schema.AttachCoverageComplete
	}
	switch {
	case v.AttachFailed > 0 && mode == "required":
		v.AttachStatus = "fail"
	case v.AttachFailed > 0:
		v.AttachStatus = "warn"
	case v.AttachAttempted > 0:
		v.AttachStatus = "pass"
	default:
		v.AttachStatus = "skipped"
	}
	tg.Validation = v
	return tg
}

// legacyAttach is a report from before attach accounting: aggregate counts only.
func legacyAttach(tg schema.Target, mode string, attempted, passed, failed int) schema.Target {
	tg.Validation = &schema.Validation{LoadStatus: "pass", AttachMode: mode, AttachAttempted: attempted, AttachPassed: passed, AttachFailed: failed}
	return tg
}

const tpSec = "tracepoint/syscalls/sys_enter_getpid"

func attached(name string) ap { return ap{name, tpSec, schema.AttachOutcomeAttached, 0} }
func failed(name string) ap   { return ap{name, tpSec, schema.AttachOutcomeFailed, -2} }

func compat() schema.Target { return target("ubuntu-22.04-5.15", schema.VerdictCompatible, true) }
func incompat() schema.Target {
	return target("ubuntu-22.04-5.15", schema.VerdictIncompatible, true)
}

func TestBestEffortAttachedToFailedIsANewRegression(t *testing.T) {
	// Both runs are COMPATIBLE: best-effort tolerates attach failures. The
	// verdicts are identical and the regression is real.
	base := withAttach(compat(), "best-effort", attached("a"), attached("b"))
	cand := withAttach(compat(), "best-effort", attached("a"), failed("b"))
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != NewRegression {
		t.Fatalf("attached -> failed hidden as %s: %s", c.Classification, c.Reason)
	}
	if !strings.Contains(c.Reason, `"b"`) {
		t.Fatalf("reason must name the program: %s", c.Reason)
	}
}

func TestAttachRegressionSurvivesAPolicyChange(t *testing.T) {
	// The same bpf_program__attach succeeded and then failed; the requested
	// policy changed what the verdict does with that, not the fact itself.
	base := withAttach(compat(), "best-effort", attached("a"))
	cand := withAttach(incompat(), "required", failed("a"))
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != NewRegression {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
	if !strings.Contains(c.Reason, "attach mode") {
		t.Fatalf("the policy change must still be reported: %s", c.Reason)
	}
}

func TestAttachRegressionIsNotHiddenUnderAnExistingIncompatibility(t *testing.T) {
	base := withAttach(incompat(), "required", attached("a"), failed("b"))
	cand := withAttach(incompat(), "required", failed("a"), failed("b"))
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != NewRegression {
		t.Fatalf("a newly failing program behind a known failure was reported as %s", c.Classification)
	}
}

func TestUnchangedAttachFailureIsNotANewRegression(t *testing.T) {
	base := withAttach(compat(), "best-effort", attached("a"), failed("b"))
	cand := withAttach(compat(), "best-effort", attached("a"), failed("b"))
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != UnchangedCompatible {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestAttachComparabilityChangesAreInconclusive(t *testing.T) {
	cases := []struct {
		name       string
		base, cand schema.Target
		want       string
	}{
		{"validator capability changed",
			withAttach(compat(), "best-effort", attached("a")),
			withAttach(compat(), "best-effort", ap{"a", tpSec, schema.AttachOutcomeNotAttachable, 0}),
			"capability"},
		{"program left the selected scope",
			withAttach(compat(), "best-effort", attached("a"), attached("b")),
			withAttach(compat(), "best-effort", attached("a"), ap{"b", tpSec, schema.AttachOutcomeNotSelected, 0}),
			"scope"},
		{"section changed under the same name",
			withAttach(compat(), "best-effort", attached("a")),
			withAttach(compat(), "best-effort", ap{"a", "kprobe/do_sys_open", schema.AttachOutcomeAttached, 0}),
			"section"},
		{"candidate adds a program whose attach failed",
			withAttach(compat(), "best-effort", attached("a")),
			withAttach(compat(), "best-effort", attached("a"), failed("new")),
			"new"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := onlyCell(t, build(t, report(tc.base), report(tc.cand)))
			if c.Classification != Inconclusive {
				t.Fatalf("got %s: %s", c.Classification, c.Reason)
			}
			if !strings.Contains(c.Reason, tc.want) {
				t.Fatalf("reason %q must mention %q", c.Reason, tc.want)
			}
		})
	}
}

func TestProgramSetChangesWithoutFailuresStayComparable(t *testing.T) {
	// A release that removes a program, or adds one that attaches, has not
	// regressed attach on anything it still ships.
	base := withAttach(compat(), "best-effort", attached("a"), attached("gone"))
	cand := withAttach(compat(), "best-effort", attached("a"), attached("added"))
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != UnchangedCompatible {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
	if !strings.Contains(c.Reason, "gone") {
		t.Fatalf("a removed program must be visible in the reason: %s", c.Reason)
	}
}

func TestMissingHistoricalAccountingIsNotEquivalentCoverage(t *testing.T) {
	t.Run("old baseline, candidate shows a failure", func(t *testing.T) {
		base := legacyAttach(compat(), "best-effort", 2, 2, 0)
		cand := withAttach(compat(), "best-effort", attached("a"), failed("b"))
		c := onlyCell(t, build(t, report(base), report(cand)))
		if c.Classification != Inconclusive || !strings.Contains(c.Reason, "the baseline does not record per-program attach accounting") {
			t.Fatalf("got %s: %s", c.Classification, c.Reason)
		}
	})
	t.Run("both old, candidate aggregate shows a failure", func(t *testing.T) {
		base := legacyAttach(compat(), "best-effort", 2, 2, 0)
		cand := legacyAttach(compat(), "best-effort", 2, 1, 1)
		c := onlyCell(t, build(t, report(base), report(cand)))
		if c.Classification != Inconclusive || !strings.Contains(c.Reason, "neither side records") {
			t.Fatalf("a best-effort attach failure was hidden as %s: %s", c.Classification, c.Reason)
		}
	})
	t.Run("both old, candidate status says warn without a count", func(t *testing.T) {
		base := legacyAttach(compat(), "best-effort", 1, 1, 0)
		cand := legacyAttach(compat(), "best-effort", 0, 0, 0)
		cand.Validation.AttachStatus = "warn"
		c := onlyCell(t, build(t, report(base), report(cand)))
		if c.Classification != Inconclusive {
			t.Fatalf("got %s", c.Classification)
		}
	})
	t.Run("old baseline, candidate attached everything", func(t *testing.T) {
		base := legacyAttach(compat(), "best-effort", 1, 1, 0)
		cand := withAttach(compat(), "best-effort", attached("a"))
		c := onlyCell(t, build(t, report(base), report(cand)))
		if c.Classification != UnchangedCompatible {
			t.Fatalf("nothing failed in the candidate; got %s: %s", c.Classification, c.Reason)
		}
	})
	t.Run("both old, no failures: unchanged behaviour", func(t *testing.T) {
		base := legacyAttach(compat(), "best-effort", 1, 1, 0)
		cand := legacyAttach(compat(), "best-effort", 1, 1, 0)
		c := onlyCell(t, build(t, report(base), report(cand)))
		if c.Classification != UnchangedCompatible {
			t.Fatalf("got %s", c.Classification)
		}
	})
}

func TestAttachRegressionNeedsAnEstablishedEnvironment(t *testing.T) {
	base := withAttach(compat(), "best-effort", attached("a"))
	cand := withAttach(mismatched(compat()), "best-effort", failed("a"))
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification == NewRegression {
		t.Fatal("a failure on a kernel the obligation does not name is not a regression of it")
	}
}

func TestLoadRegressionIsNotDowngradedByAttachChanges(t *testing.T) {
	base := withAttach(compat(), "best-effort", attached("a"))
	cand := incompat()
	cand.Validation = &schema.Validation{LoadStatus: "fail", AttachMode: "best-effort"}
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != NewRegression {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestTruncatedRecordsWithUnseenFailuresAreInconclusive(t *testing.T) {
	base := withAttach(compat(), "best-effort", attached("a"))
	cand := withAttach(compat(), "best-effort", attached("a"))
	// 70 programs, one failure that falls outside the 64 records written.
	cand.Validation.AttachProgramCount = 70
	cand.Validation.AttachSelected = 70
	cand.Validation.AttachAttachable = 70
	cand.Validation.AttachAttempted = 70
	cand.Validation.AttachPassed = 69
	cand.Validation.AttachFailed = 1
	cand.Validation.AttachRecordsTruncated = true
	cand.Validation.AttachStatus = "warn"
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != Inconclusive {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestDeletingAttachEvidenceNeverBuysGreen(t *testing.T) {
	// The Gate 2.1 property for attach accounting: starting from a proven
	// per-program regression, deleting candidate attach evidence must not
	// produce a green cell.
	base := withAttach(compat(), "best-effort", attached("a"))
	green := map[string]bool{UnchangedCompatible: true, Fixed: true, CoverageAdded: true}
	mutations := map[string]func(*schema.Target){
		"strip accounting": func(tg *schema.Target) {
			tg.Validation.AttachAccounting = ""
			tg.Validation.AttachPrograms = nil
		},
		"strip accounting and failure count": func(tg *schema.Target) {
			tg.Validation.AttachAccounting = ""
			tg.Validation.AttachPrograms = nil
			tg.Validation.AttachFailed = 0
			tg.Validation.AttachAttempted = 0
		},
		"strip accounting, failure count and status": func(tg *schema.Target) {
			tg.Validation.AttachAccounting = ""
			tg.Validation.AttachPrograms = nil
			tg.Validation.AttachFailed = 0
			tg.Validation.AttachAttempted = 0
			tg.Validation.AttachStatus = ""
		},
		"drop the program record": func(tg *schema.Target) {
			tg.Validation.AttachPrograms = nil
			tg.Validation.AttachRecordsTruncated = true
		},
		"drop the validation block": func(tg *schema.Target) { tg.Validation = nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			cand := withAttach(compat(), "best-effort", failed("a"))
			mutate(&cand)
			d, err := buildErr(report(base), report(cand))
			if err != nil {
				return // refusing the evidence is not green
			}
			if c := onlyCell(t, d); green[c.Classification] {
				t.Fatalf("deleting attach evidence bought %s: %s", c.Classification, c.Reason)
			}
		})
	}
}

// Counterexamples from the independent review: records that keep the
// arithmetic but break the attach-phase invariants, or delete a regression
// through the truncation path.
func TestAttachPhaseInvariantsCannotBeBentIntoGreen(t *testing.T) {
	green := map[string]bool{UnchangedCompatible: true, Fixed: true, CoverageAdded: true}
	notAttempted := ap{"a", tpSec, schema.AttachOutcomeNotAttempted, 0}
	cases := map[string]func() schema.Target{
		"attached -> never attempted, load passed, mode unchanged": func() schema.Target {
			return withAttach(compat(), "best-effort", notAttempted)
		},
		"same, claiming coverage complete and status pass": func() schema.Target {
			tg := withAttach(compat(), "best-effort", notAttempted)
			tg.Validation.AttachCoverage = schema.AttachCoverageComplete
			tg.Validation.AttachStatus = "pass"
			return tg
		},
		"regression record deleted through truncation": func() schema.Target {
			tg := withAttach(compat(), "best-effort", failed("a"))
			v := tg.Validation
			v.AttachPrograms = nil
			v.AttachRecordsTruncated = true
			v.AttachFailed, v.AttachAttempted = 0, 0
			v.AttachStatus = "skipped"
			return tg
		},
		"status pass next to a failure": func() schema.Target {
			tg := withAttach(compat(), "best-effort", attached("a"), failed("b"))
			tg.Validation.AttachStatus = "pass"
			return tg
		},
		"coverage none while every program was tried": func() schema.Target {
			tg := withAttach(compat(), "best-effort", attached("a"))
			tg.Validation.AttachCoverage = schema.AttachCoverageNone
			return tg
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			base := withAttach(compat(), "best-effort", attached("a"), attached("b"))
			d, err := buildErr(report(base), report(mk()))
			if err != nil {
				var inv *InvalidEvidenceError
				if !errors.As(err, &inv) {
					t.Fatalf("unexpected error type: %v", err)
				}
				return
			}
			if c := onlyCell(t, d); green[c.Classification] {
				t.Fatalf("bought %s: %s", c.Classification, c.Reason)
			}
		})
	}
}

// Round-2 review counterexamples.
func TestLoadStatusCannotBeBentToSkipThePhaseInvariant(t *testing.T) {
	green := map[string]bool{UnchangedCompatible: true, Fixed: true, CoverageAdded: true}
	for _, load := range []string{"fail", ""} {
		t.Run("load_status="+load, func(t *testing.T) {
			base := withAttach(compat(), "best-effort", attached("a"))
			cand := withAttach(compat(), "best-effort", ap{"a", tpSec, schema.AttachOutcomeNotAttempted, 0})
			v := cand.Validation
			v.LoadStatus = load
			v.AttachCoverage = schema.AttachCoverageNotEvaluated
			v.AttachStatus = "skipped"
			d, err := buildErr(report(base), report(cand))
			if err != nil {
				return
			}
			if c := onlyCell(t, d); green[c.Classification] {
				t.Fatalf("bought %s: %s", c.Classification, c.Reason)
			}
		})
	}
}

func TestTruncatedBaselineCannotHideAShrinkingScope(t *testing.T) {
	var bprogs, cprogs []ap
	for i := 0; i < 64; i++ {
		bprogs = append(bprogs, attached(fmt.Sprintf("p%02d", i)))
		cprogs = append(cprogs, attached(fmt.Sprintf("p%02d", i)))
	}
	base := withAttach(compat(), "best-effort", bprogs...)
	bv := base.Validation
	bv.AttachProgramCount, bv.AttachSelected, bv.AttachAttachable = 65, 65, 65
	bv.AttachAttempted, bv.AttachPassed = 65, 65
	bv.AttachRecordsTruncated = true
	// The 65th program, outside the baseline's records, is now not selected.
	cand := withAttach(compat(), "best-effort", append(cprogs, ap{"p64", tpSec, schema.AttachOutcomeNotSelected, 0})...)
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != Inconclusive {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestCandidateThatAttachesNothingIsNotStillSupported(t *testing.T) {
	base := withAttach(compat(), "best-effort", attached("a"))
	cand := withAttach(compat(), "best-effort")
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != Inconclusive {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestUnexercisedRequiredAttachIsExplainedAsSuch(t *testing.T) {
	base := withAttach(compat(), "required", attached("a"))
	cand := withAttach(target("ubuntu-22.04-5.15", schema.VerdictUnsupported, true), "required",
		attached("a"), ap{"x", "xdp", schema.AttachOutcomeNotAttachable, 0})
	cand.ClassificationCode = "ATTACH_NOT_EXERCISED"
	c := onlyCell(t, build(t, report(base), report(cand)))
	if c.Classification != Inconclusive || !strings.Contains(c.Reason, "ATTACH_NOT_EXERCISED") ||
		strings.Contains(c.Reason, "could not execute this environment") {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestTruncatedCandidateComparabilityRestsOnWholeObjectState(t *testing.T) {
	base := withAttach(compat(), "best-effort", attached("a"), attached("b"))
	// The candidate has 70 programs and records 64 of them; "a" is not among
	// the records. Whatever it is, nothing can have regressed when every one
	// of the 70 programs attached: "a" is either attached beyond the records
	// or no longer in the object.
	mk := func(passed, notAttachable int) schema.Target {
		var progs []ap
		progs = append(progs, attached("b"))
		for i := 0; i < 63; i++ {
			progs = append(progs, attached(fmt.Sprintf("p%02d", i)))
		}
		cand := withAttach(compat(), "best-effort", progs...)
		v := cand.Validation
		v.AttachProgramCount, v.AttachSelected = 70, 70
		v.AttachAttachable, v.AttachNotAttachable = 70-notAttachable, notAttachable
		v.AttachAttempted, v.AttachPassed = passed, passed
		v.AttachRecordsTruncated = true
		if notAttachable > 0 {
			v.AttachCoverage = schema.AttachCoveragePartial
		}
		return cand
	}
	if c := onlyCell(t, build(t, report(base), report(mk(70, 0)))); c.Classification != UnchangedCompatible {
		t.Fatalf("every program attached: got %s: %s", c.Classification, c.Reason)
	}
	// One unrecorded program is not attachable: "a" may be that one.
	if c := onlyCell(t, build(t, report(base), report(mk(69, 1)))); c.Classification != Inconclusive {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
}

func TestMalformedAttachAccountingIsRefused(t *testing.T) {
	good := func() schema.Target { return withAttach(compat(), "best-effort", attached("a"), failed("b")) }
	cases := []struct {
		name   string
		mutate func(*schema.Validation)
	}{
		{"duplicate program", func(v *schema.Validation) { v.AttachPrograms[1].Name = "a" }},
		{"empty name", func(v *schema.Validation) { v.AttachPrograms[0].Name = "" }},
		{"unknown outcome", func(v *schema.Validation) { v.AttachPrograms[0].Outcome = "fine" }},
		{"records claim more failures than the counts", func(v *schema.Validation) { v.AttachFailed = 0; v.AttachAttempted = 1 }},
		{"attempted != passed + failed", func(v *schema.Validation) { v.AttachAttempted = 5 }},
		{"records without v1", func(v *schema.Validation) { v.AttachAccounting = "" }},
		{"oversized list", func(v *schema.Validation) {
			for i := 0; i < 300; i++ {
				v.AttachPrograms = append(v.AttachPrograms, schema.AttachProgram{Name: strings.Repeat("x", i+1), Outcome: schema.AttachOutcomeAttached, Selected: true})
			}
		}},
		{"oversized name", func(v *schema.Validation) { v.AttachPrograms[0].Name = strings.Repeat("n", 5000) }},
		{"not-selected program that attached", func(v *schema.Validation) { v.AttachPrograms[0].Selected = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cand := good()
			tc.mutate(cand.Validation)
			_, err := buildErr(report(withAttach(compat(), "best-effort", attached("a"), attached("b"))), report(cand))
			var inv *InvalidEvidenceError
			if !errors.As(err, &inv) {
				t.Fatalf("malformed attach accounting accepted: err=%v", err)
			}
		})
	}
}
