package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

func renderMarkdownFile(t *testing.T, r schema.ReportV01) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.md")
	if err := WriteMarkdown(p, r); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The --markdown report shows the gate, derived from the targets. A
// summary.gate field that claims more than the targets support must never
// produce an "enforced" line.
func TestMarkdownReportShowsGateFromTargets(t *testing.T) {
	opt := schema.ReportV01{
		Summary: schema.SummaryInfo{Status: "pass", Verdict: schema.VerdictCompatible, Gate: schema.GateEnforced}, // forged
		Targets: []schema.Target{{ProfileID: "k", Required: false, Status: "fail", Verdict: schema.VerdictIncompatible}},
	}
	md := renderMarkdownFile(t, opt)
	if !strings.Contains(md, "- Gate: `none`") || !strings.Contains(md, "not a compatibility gate") {
		t.Fatalf("optional-only report must show Gate none:\n%s", md)
	}
	if strings.Contains(md, "- Gate: `enforced`") {
		t.Fatalf("a forged summary.gate must not manufacture an enforced gate:\n%s", md)
	}

	req := schema.ReportV01{
		Summary: schema.SummaryInfo{Status: "pass", Verdict: schema.VerdictCompatible},
		Targets: []schema.Target{{ProfileID: "k", Required: true, Status: "pass", Verdict: schema.VerdictCompatible}},
	}
	if md := renderMarkdownFile(t, req); !strings.Contains(md, "- Gate: `enforced`") {
		t.Fatalf("gated report must show Gate enforced:\n%s", md)
	}

	// No targets at all (e.g. a truncated report) is never a gate.
	if md := renderMarkdownFile(t, schema.ReportV01{Summary: schema.SummaryInfo{Status: "pass", Gate: schema.GateEnforced}}); !strings.Contains(md, "- Gate: `none`") {
		t.Fatalf("report without targets must show Gate none:\n%s", md)
	}
}
