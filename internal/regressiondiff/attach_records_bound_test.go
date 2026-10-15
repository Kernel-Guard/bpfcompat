package regressiondiff

import (
	"errors"
	"strings"
	"testing"
)

// With complete per-program records (the validator records up to 1024
// programs), objects larger than the old 64-record cap compare per program.

const validatorRecordBound = 1024 // must equal MAX_PROGRAM_RECORDS in the validator

func TestDiffRecordBoundMatchesTheValidator(t *testing.T) {
	if maxDiffAttachRecords != validatorRecordBound {
		t.Fatalf("diff bound %d != validator bound %d", maxDiffAttachRecords, validatorRecordBound)
	}
}

func TestCompleteRecordsAboveSixtyFourComparePerProgram(t *testing.T) {
	t.Run("identical evidence with a non-attached program is unchanged", func(t *testing.T) {
		// Under the old cap this was INCONCLUSIVE forever (truncated, mixed states).
		progs := append(attachedN("p", 205), notAttachable("lsm_hook"))
		base := withAttach(compat(), "best-effort", progs...)
		cand := withAttach(compat(), "best-effort", progs...)
		c := onlyCell(t, build(t, report(base), report(cand)))
		if c.Classification != UnchangedCompatible {
			t.Fatalf("got %s: %s", c.Classification, c.Reason)
		}
	})
	t.Run("a regression at program 200 is named", func(t *testing.T) {
		bp := attachedN("p", 206)
		cp := attachedN("p", 206)
		cp[200] = failed(cp[200].name)
		c := onlyCell(t, build(t, report(withAttach(compat(), "best-effort", bp...)), report(withAttach(compat(), "best-effort", cp...))))
		if c.Classification != NewRegression || !strings.Contains(c.Reason, `"p200"`) {
			t.Fatalf("got %s: %s", c.Classification, c.Reason)
		}
	})
	t.Run("a swap of states at programs 100 and 150 is not hidden", func(t *testing.T) {
		bp := attachedN("p", 206)
		cp := attachedN("p", 206)
		bp[100] = notAttachable(bp[100].name)
		cp[150] = notAttachable(cp[150].name)
		c := onlyCell(t, build(t, report(withAttach(compat(), "best-effort", bp...)), report(withAttach(compat(), "best-effort", cp...))))
		if c.Classification != Inconclusive {
			t.Fatalf("got %s: %s", c.Classification, c.Reason)
		}
	})
}

func TestRecordsAtTheBoundStayConservative(t *testing.T) {
	// 1100 programs, 1024 recorded: the truncation rule still applies.
	progs := append(attachedN("p", 1098), attached("x"), notAttachable("y"))
	base := keepRecords(compat(), "best-effort", validatorRecordBound, progs...)
	cand := keepRecords(compat(), "best-effort", validatorRecordBound, progs...)
	if c := onlyCell(t, build(t, report(base), report(cand))); c.Classification != Inconclusive {
		t.Fatalf("got %s: %s", c.Classification, c.Reason)
	}
	all := attachedN("p", 1100)
	base = keepRecords(compat(), "best-effort", validatorRecordBound, all...)
	cand = keepRecords(compat(), "best-effort", validatorRecordBound, all...)
	if c := onlyCell(t, build(t, report(base), report(cand))); c.Classification != UnchangedCompatible {
		t.Fatalf("all attached at the bound: got %s: %s", c.Classification, c.Reason)
	}
}

func TestRecordsAboveTheBoundAreRefused(t *testing.T) {
	progs := attachedN("p", validatorRecordBound+1)
	_, err := buildErr(report(withAttach(compat(), "best-effort", progs...)), report(withAttach(compat(), "best-effort", progs...)))
	var inv *InvalidEvidenceError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidEvidenceError, got %v", err)
	}
}
