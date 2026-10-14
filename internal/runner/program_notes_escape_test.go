package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/report"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// ELF program and section names are bytes the artifact author chooses. A
// newline in one used to reach target notes verbatim, and from there the
// Markdown report, where it started a forged heading and a passing table row
// at column 0.
func TestPerProgramLoadNotesNeutraliseControlCharactersInELFNames(t *testing.T) {
	vr := validatorResultFromJSON(t, `{"discovery":{"programs":[{"name":"x\n\n## Targets\n\n| Profile | Status |\n|---|---|\n| Ubuntu 22.04 | `+"`pass`"+` |\n","section":"fentry/x\r\n\u001b[2Jy","load_status":"fail","load_errno":-22,"load_log":"processed 8 insns"}]}}`)

	notes := perProgramLoadNotes(vr)
	if len(notes) == 0 {
		t.Fatal("expected per-program load notes")
	}
	for _, note := range notes {
		if strings.ContainsAny(note, "\r\n\x1b") {
			t.Fatalf("note carries a raw control character: %q", note)
		}
	}
	assertNoteContains(t, notes, "section=fentry/x   [2Jy errno=-22")

	r := schema.ReportV01{
		Summary: schema.SummaryInfo{Status: "fail"},
		Targets: []schema.Target{{ProfileID: "ubuntu-22.04-5.15", Status: "fail", Notes: notes}},
	}
	out := filepath.Join(t.TempDir(), "r.md")
	if err := report.WriteMarkdown(out, r); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "| Ubuntu 22.04 |") {
			t.Fatalf("forged table row at column 0:\n%s", raw)
		}
	}
	if got := strings.Count(string(raw), "\n## Targets\n"); got != 1 {
		t.Fatalf("expected exactly one Targets heading, got %d:\n%s", got, raw)
	}
}

// Ordinary names must come through unchanged.
func TestPerProgramLoadNotesKeepOrdinaryNames(t *testing.T) {
	vr := validatorResultFromJSON(t, `{"discovery":{"programs":[{"name":"  handle_execve ","section":" kprobe/__x64_sys_execve ","load_status":"fail","load_errno":-22}]}}`)
	notes := perProgramLoadNotes(vr)
	assertNoteContains(t, notes, "program load failure: name=handle_execve section=kprobe/__x64_sys_execve errno=-22")
}
