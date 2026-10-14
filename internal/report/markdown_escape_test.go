package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/classifier"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// hostileSection is a program section name an artifact author fully
// controls: ELF section names are arbitrary bytes except NUL, and the
// classifier quotes them into the reason with %q, which escapes quotes and
// control bytes but no Markdown metacharacter.
const hostileSection = "fentry/x` ![t](https://evil.example/pixel.png) " +
	"[**All kernels PASS - view signed log**](https://evil.example/login) " +
	"<img src=x onerror=alert(1)> `"

// hostileProgramName forges a heading and a passing table row if it reaches
// the Markdown report with its newlines intact.
const hostileProgramName = "x\n\n## Targets\n\n| Profile | Status |\n|---|---|\n| Ubuntu 22.04 | `pass` |\n"

// assertNoMarkdownInjection fails when any construct an artifact author could
// use to spoof the rendered report survives: inline links or images, raw
// HTML, bold text, or a line that starts a heading or table row it forged.
func assertNoMarkdownInjection(t *testing.T, out string) {
	t.Helper()
	prose := stripCodeSpans(out)
	for _, live := range []string{"](http", "<img", "**All kernels PASS"} {
		if unescapedIndex(prose, live) >= 0 {
			t.Errorf("rendered Markdown contains live %q:\n%s", live, out)
		}
	}
	for _, bad := range []string{
		"\n| Ubuntu 22.04 |",
		"\n## Targets\n\n| Profile | Status |",
	} {
		if strings.Contains(out, bad) {
			t.Errorf("rendered Markdown contains injected %q:\n%s", bad, out)
		}
	}
	if regexp.MustCompile(`\x1b`).MatchString(out) {
		t.Errorf("rendered Markdown contains a raw ESC byte:\n%q", out)
	}
}

// stripCodeSpans removes CommonMark code spans line by line: a backtick run
// that is not backslash-escaped opens a span that the next run of exactly the
// same length closes. What remains is the text a renderer interprets as
// Markdown, so a link that escaped its code span (because the value carried
// its own backtick) is still found.
func stripCodeSpans(s string) string {
	lines := strings.Split(s, "\n")
	for li, line := range lines {
		var b strings.Builder
		for i := 0; i < len(line); {
			if line[i] != '`' || (i > 0 && line[i-1] == '\\') {
				b.WriteByte(line[i])
				i++
				continue
			}
			n := 0
			for i+n < len(line) && line[i+n] == '`' {
				n++
			}
			closeAt := -1
			for j := i + n; j < len(line); {
				if line[j] != '`' {
					j++
					continue
				}
				m := 0
				for j+m < len(line) && line[j+m] == '`' {
					m++
				}
				if m == n {
					closeAt = j + m
					break
				}
				j += m
			}
			if closeAt < 0 {
				b.WriteString(line[i : i+n])
				i += n
				continue
			}
			b.WriteString("<code/>")
			i = closeAt
		}
		lines[li] = b.String()
	}
	return strings.Join(lines, "\n")
}

// unescapedIndex returns the index of the first occurrence of needle that is
// not preceded by an odd number of backslashes (that is, whose first byte is
// a live Markdown character), or -1.
func unescapedIndex(s, needle string) int {
	for off := 0; ; {
		i := strings.Index(s[off:], needle)
		if i < 0 {
			return -1
		}
		i += off
		slashes := 0
		for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
			slashes++
		}
		if slashes%2 == 0 {
			return i
		}
		off = i + 1
	}
}

func hostileReport() schema.ReportV01 {
	cl := classifier.Classify(classifier.Input{
		LoadStatus:      "fail",
		LoadError:       "load failed",
		LibbpfLog:       "libbpf: prog 'x': failed to load: -22",
		KernelRelease:   "4.15.0-213-generic",
		ProgramSections: []string{hostileSection},
	})
	return schema.ReportV01{
		Run: schema.RunInfo{ID: "run-1"},
		Artifact: schema.Artifact{
			Path:     "/tmp/a`[click](https://evil.example/a)`.bpf.o",
			BaseName: "a`[click](https://evil.example/a)`.bpf.o",
			SHA256:   strings.Repeat("a", 64),
		},
		Summary: schema.SummaryInfo{
			Status:  "fail",
			Verdict: "INCOMPATIBLE",
			Notes: []string{
				"note " + hostileSection,
				// One unclosed backtick: it must not pair with anything.
				"odd` [**All kernels PASS**](https://evil.example/n) <img src=x>",
			},
		},
		Targets: []schema.Target{{
			ProfileID:                "ubuntu-18.04-4.15",
			Required:                 true,
			Status:                   "fail",
			ClassificationCode:       cl.Code,
			ClassificationConfidence: cl.Confidence,
			ClassificationReason:     cl.Reason,
			Notes: []string{
				"program load failure: name=" + hostileProgramName + " section=fentry/x errno=22",
				"escape \x1b[2J sequence",
			},
			Functional: &schema.Functional{
				Status: "fail",
				Tests: []schema.FunctionalTest{{
					Name:   "t`[x](https://evil.example/t)`",
					Status: "fail",
					Error:  hostileProgramName + " [y](https://evil.example/e)",
				}},
			},
		}, {
			ProfileID: "p`[z](https://evil.example/p)`\n| Ubuntu 22.04 | `pass` |",
			Status:    "fail",
		}},
	}
}

func TestActionSummaryEscapesArtifactControlledStrings(t *testing.T) {
	out := BuildGitHubActionSummary(hostileReport(), ActionSummaryOptions{})
	assertNoMarkdownInjection(t, out)
	// The hostile reason must still be shown, as literal text.
	if !strings.Contains(out, "odd\\` [\\*\\*All kernels PASS\\*\\*\\](https://evil.example/n) \\<img src=x>") {
		t.Errorf("expected the escaped reason text to remain visible:\n%s", out)
	}
}

func TestMarkdownReportEscapesArtifactControlledStrings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.md")
	if err := WriteMarkdown(p, hostileReport()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	assertNoMarkdownInjection(t, out)
	if got := strings.Count(out, "\n## Targets\n"); got != 1 {
		t.Errorf("expected exactly one Targets heading, got %d:\n%s", got, out)
	}
}

// TestRenderersAreByteIdenticalForOrdinaryReports pins the rendered output of
// an ordinary report to goldens captured from the renderers before the
// escaping change: escaping must only alter hostile or odd strings.
func TestRenderersAreByteIdenticalForOrdinaryReports(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "ordinary-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r schema.ReportV01
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(t.TempDir(), "r.md")
	if err := WriteMarkdown(p, r); err != nil {
		t.Fatal(err)
	}
	gotMD, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	wantMD, err := os.ReadFile(filepath.Join("testdata", "ordinary-report.golden.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotMD, wantMD) {
		t.Errorf("Markdown report drifted for an ordinary report:\n--- got ---\n%s\n--- want ---\n%s", gotMD, wantMD)
	}

	gotSummary := BuildGitHubActionSummary(r, ActionSummaryOptions{})
	wantSummary, err := os.ReadFile(filepath.Join("testdata", "ordinary-report.golden.summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	if gotSummary != string(wantSummary) {
		t.Errorf("Action summary drifted for an ordinary report:\n--- got ---\n%s\n--- want ---\n%s", gotSummary, wantSummary)
	}
}
