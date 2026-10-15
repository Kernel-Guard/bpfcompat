package regressiondiff

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Property check of the truncation rule over generated objects around the
// 64-record boundary: (1) when either side's records are truncated, a green
// cell (UNCHANGED_COMPATIBLE, FIXED) requires every program on both sides to
// have attached; (2) a program recorded as attached at baseline and failed in
// the candidate is NEW_REGRESSION whatever else is truncated, and carries an
// attribution.
func TestTruncationPropertyNoUnjustifiedGreenAndProvenRegressionsSurvive(t *testing.T) {
	rng := rand.New(rand.NewSource(254))
	outcomes := []func(string) ap{attached, attached, attached, failed, notAttachable, notSelected}
	gen := func(n int) []ap {
		ps := make([]ap, n)
		for i := range ps {
			name := fmt.Sprintf("p%02d", i)
			if rng.Intn(8) == 0 {
				ps[i] = outcomes[rng.Intn(len(outcomes))](name)
			} else {
				ps[i] = attached(name)
			}
		}
		// Occasionally reorder across the boundary.
		if rng.Intn(3) == 0 && n > 64 {
			i, j := 60+rng.Intn(4), 64+rng.Intn(n-64)
			ps[i], ps[j] = ps[j], ps[i]
		}
		return ps
	}
	allAttached := func(ps []ap) bool {
		for _, p := range ps {
			if p.outcome != schema.AttachOutcomeAttached {
				return false
			}
		}
		return true
	}
	green := map[string]bool{UnchangedCompatible: true, Fixed: true}
	var greens, regressions int
	for iter := 0; iter < 3000; iter++ {
		bp, cp := gen(62+rng.Intn(8)), gen(62+rng.Intn(8))
		// Plant a proven regression inside both sides' records in a third of the cases.
		planted := rng.Intn(3) == 0
		if planted {
			k := rng.Intn(60)
			bp[k], cp[k] = attached(fmt.Sprintf("p%02d", k)), failed(fmt.Sprintf("p%02d", k))
		}
		base := keepRecords(compat(), "best-effort", 64, bp...)
		cand := keepRecords(compat(), "best-effort", 64, cp...)
		br, cr := report(base), report(cand)
		if rng.Intn(2) == 0 {
			cr.Artifact.SHA256 = "bbb"
		}
		c := onlyCell(t, build(t, br, cr))
		truncated := len(bp) > 64 || len(cp) > 64
		if truncated && green[c.Classification] && (!allAttached(bp) || !allAttached(cp)) {
			t.Fatalf("iter %d: truncated comparison is %s although not every program attached on both sides: %s\nbase=%v\ncand=%v",
				iter, c.Classification, c.Reason, bp, cp)
		}
		if planted {
			if c.Classification != NewRegression || c.Attribution == "" {
				t.Fatalf("iter %d: proven regression lost: %s/%q: %s", iter, c.Classification, c.Attribution, c.Reason)
			}
			regressions++
		}
		if green[c.Classification] {
			greens++
		}
	}
	// The generator must exercise both branches.
	if greens == 0 || regressions == 0 {
		t.Fatalf("generator did not exercise both properties: greens=%d regressions=%d", greens, regressions)
	}
}
