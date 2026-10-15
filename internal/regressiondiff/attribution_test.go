package regressiondiff

import (
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// Attribution is an observation about recorded inputs, not a cause. These
// tests pin that wording and the handling of identities only one side records.

// causalPhrases are wordings that would turn "these recorded inputs differ"
// into "this input caused the outcome". None may appear in any attribution.
var causalPhrases = []string{"follows it", "follows the", "caused", "because the artifact", "due to"}

const unrecordedDisclaimer = "inputs the reports do not record"

func withOS(tg schema.Target, id, version string) schema.Target {
	env := *tg.Environment
	env.ObservedOSID, env.ObservedOSVersionID = id, version
	tg.Environment = &env
	return tg
}

func assertObservational(t *testing.T, c Cell) {
	t.Helper()
	for _, p := range causalPhrases {
		if strings.Contains(c.Reason, p) {
			t.Fatalf("reason claims causation (%q): %s", p, c.Reason)
		}
	}
	if !strings.Contains(c.Reason, unrecordedDisclaimer) {
		t.Fatalf("reason does not say unrecorded inputs may also differ: %s", c.Reason)
	}
}

func TestAttributionNeverClaimsCause(t *testing.T) {
	cases := []struct {
		name                         string
		bSHA, cSHA, bKernel, cKernel string
		want                         string
	}{
		{"artifact only", "aaa", "bbb", "5.15.0-186-generic", "5.15.0-186-generic", AttributionArtifactOnly},
		{"environment only", "aaa", "aaa", "5.15.0-186-generic", "5.15.0-189-generic", AttributionEnvironmentOnly},
		{"multiple", "aaa", "bbb", "5.15.0-186-generic", "5.15.0-189-generic", AttributionMultiple},
		{"none recorded", "aaa", "aaa", "5.15.0-186-generic", "5.15.0-186-generic", AttributionNoneRecorded},
		{"unknown", "", "bbb", "5.15.0-186-generic", "5.15.0-186-generic", AttributionUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br, cr := regressionPair(tc.bSHA, tc.cSHA, tc.bKernel, tc.cKernel)
			c := onlyCell(t, build(t, br, cr))
			if c.Classification != NewRegression || c.Attribution != tc.want {
				t.Fatalf("got %s/%s: %s", c.Classification, c.Attribution, c.Reason)
			}
			assertObservational(t, c)
		})
	}
	t.Run("validator only", func(t *testing.T) {
		br, cr := regressionPair("aaa", "aaa", "5.15.0-186-generic", "5.15.0-186-generic")
		br.Validator = &schema.BinaryIdentity{SHA256: "v1"}
		cr.Validator = &schema.BinaryIdentity{SHA256: "v2"}
		c := onlyCell(t, build(t, br, cr))
		if c.Attribution != AttributionValidatorOnly {
			t.Fatalf("got %s: %s", c.Attribution, c.Reason)
		}
		assertObservational(t, c)
	})
	t.Run("fixed", func(t *testing.T) {
		br, cr := report(incompat()), report(compat())
		cr.Artifact.SHA256 = "bbb"
		c := onlyCell(t, build(t, br, cr))
		if c.Classification != Fixed || c.Attribution != AttributionArtifactOnly {
			t.Fatalf("got %s/%s: %s", c.Classification, c.Attribution, c.Reason)
		}
		assertObservational(t, c)
	})
}

// The artifact-only label must not read as "the artifact broke it" just
// because the observed kernel string matched.
func TestArtifactOnlyIsARecordedDifference(t *testing.T) {
	br, cr := regressionPair("aaa", "bbb", "5.15.0-186-generic", "5.15.0-186-generic")
	c := onlyCell(t, build(t, br, cr))
	for _, must := range []string{"among the recorded inputs", "kernel config", "boot parameters", "image contents", "host", "timing"} {
		if !strings.Contains(c.Reason, must) {
			t.Fatalf("reason must say %q: %s", must, c.Reason)
		}
	}
}

func TestOneSidedOSIdentityIsUncertainNotIgnored(t *testing.T) {
	t.Run("artifact differs, os recorded on one side only", func(t *testing.T) {
		b := compat()
		c := withOS(incompat(), "ubuntu", "22.04")
		br, cr := report(b), report(c)
		cr.Artifact.SHA256 = "bbb"
		cell := onlyCell(t, build(t, br, cr))
		// The classification is the comparison's; uncertainty never hides it.
		if cell.Classification != NewRegression {
			t.Fatalf("got %s: %s", cell.Classification, cell.Reason)
		}
		if cell.Attribution != AttributionUnknown ||
			strings.Join(cell.ChangedInputs, ",") != "artifact" ||
			strings.Join(cell.UnknownInputs, ",") != "os" {
			t.Fatalf("attribution=%s changed=%v unknown=%v: %s", cell.Attribution, cell.ChangedInputs, cell.UnknownInputs, cell.Reason)
		}
		if !strings.Contains(cell.Reason, "os") || !strings.Contains(cell.Reason, "one side") {
			t.Fatalf("reason must name the one-sided os identity: %s", cell.Reason)
		}
		assertObservational(t, cell)
	})
	t.Run("kernel differs, os recorded on one side only", func(t *testing.T) {
		// Whether the os also differs cannot add a category: the environment
		// already differs. The uncertainty is still listed.
		b := withOS(compat(), "ubuntu", "22.04")
		c := incompat()
		c.Environment.ObservedKernel = "5.15.0-189-generic"
		cell := onlyCell(t, build(t, report(b), report(c)))
		if cell.Classification != NewRegression || cell.Attribution != AttributionEnvironmentOnly ||
			strings.Join(cell.UnknownInputs, ",") != "os" {
			t.Fatalf("got %s/%s unknown=%v: %s", cell.Classification, cell.Attribution, cell.UnknownInputs, cell.Reason)
		}
		assertObservational(t, cell)
	})
	t.Run("nothing else differs, os recorded on one side only", func(t *testing.T) {
		cell := onlyCell(t, build(t, report(compat()), report(withOS(incompat(), "ubuntu", "22.04"))))
		if cell.Attribution != AttributionUnknown || strings.Join(cell.UnknownInputs, ",") != "os" {
			t.Fatalf("got %s unknown=%v: %s", cell.Attribution, cell.UnknownInputs, cell.Reason)
		}
	})
	t.Run("os recorded on both sides and equal", func(t *testing.T) {
		br, cr := report(withOS(compat(), "ubuntu", "22.04")), report(withOS(incompat(), "ubuntu", "22.04"))
		cr.Artifact.SHA256 = "bbb"
		cell := onlyCell(t, build(t, br, cr))
		if cell.Attribution != AttributionArtifactOnly || len(cell.UnknownInputs) != 0 {
			t.Fatalf("got %s unknown=%v: %s", cell.Attribution, cell.UnknownInputs, cell.Reason)
		}
		if strings.Contains(cell.Reason, "os identity is not recorded") {
			t.Fatalf("recorded os reported as unrecorded: %s", cell.Reason)
		}
	})
	t.Run("os recorded by neither side is stated, not hidden", func(t *testing.T) {
		br, cr := regressionPair("aaa", "bbb", "5.15.0-186-generic", "5.15.0-186-generic")
		cell := onlyCell(t, build(t, br, cr))
		if cell.Attribution != AttributionArtifactOnly || !strings.Contains(cell.Reason, "os identity is not recorded by either run") {
			t.Fatalf("got %s: %s", cell.Attribution, cell.Reason)
		}
	})
}

func TestOneSidedValidatorIdentityIsUncertain(t *testing.T) {
	br, cr := regressionPair("aaa", "bbb", "5.15.0-186-generic", "5.15.0-186-generic")
	cr.Validator = &schema.BinaryIdentity{SHA256: "v2"}
	cell := onlyCell(t, build(t, br, cr))
	if cell.Classification != NewRegression || cell.Attribution != AttributionUnknown ||
		strings.Join(cell.UnknownInputs, ",") != "validator" {
		t.Fatalf("got %s/%s unknown=%v: %s", cell.Classification, cell.Attribution, cell.UnknownInputs, cell.Reason)
	}
}

// Attribution is only recorded where an outcome changed.
func TestNoAttributionWithoutAChangedOutcome(t *testing.T) {
	b := withOS(incompat(), "ubuntu", "22.04")
	c := incompat()
	c.Environment.ObservedKernel = "5.15.0-189-generic"
	cell := onlyCell(t, build(t, report(b), report(c)))
	if cell.Classification != ExistingIncompatibility || cell.Attribution != "" ||
		cell.ChangedInputs != nil || cell.UnknownInputs != nil {
		t.Fatalf("got %+v", cell)
	}
}
