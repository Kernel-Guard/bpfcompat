package suite

import (
	"strings"
	"testing"
	"time"
)

func TestLoadBytesRejectsUnknownFields(t *testing.T) {
	_, err := LoadBytes([]byte(`
name: demo
unknown: true
cases:
  - name: one
    artifact: a.bpf.o
    matrix: matrix.yaml
`))
	if err == nil {
		t.Fatalf("expected unknown field error")
	}
}

func TestLoadBytesValidatesCases(t *testing.T) {
	_, err := LoadBytes([]byte(`
name: demo
cases:
  - name: one
    artifact: a.bpf.o
`))
	if err == nil || !strings.Contains(err.Error(), "matrix is required") {
		t.Fatalf("expected missing matrix error, got %v", err)
	}
}

func TestBuildRunnerConfigResolvesSuiteRelativePaths(t *testing.T) {
	spec := Spec{
		Name: "demo",
		Defaults: Defaults{
			Matrix:    "../matrices/dev-one.yaml",
			WorkDir:   "../.bpfcompat",
			ReportDir: "../reports/suites/demo",
			Timeout:   "8m",
		},
		Cases: []Case{
			{
				Name:     "functional",
				Artifact: "../examples/functional-execve/functional_execve.bpf.o",
				Manifest: "../examples/functional-execve/manifest-dev-one.yaml",
			},
		},
	}

	cfg, summary, err := buildRunnerConfig("/repo/suites", spec, spec.Cases[0], RunOptions{Concurrency: 1})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}

	assertEqual(t, cfg.ArtifactPath, "/repo/examples/functional-execve/functional_execve.bpf.o")
	assertEqual(t, cfg.ManifestPath, "/repo/examples/functional-execve/manifest-dev-one.yaml")
	assertEqual(t, cfg.MatrixPath, "/repo/matrices/dev-one.yaml")
	assertEqual(t, cfg.OutPath, "/repo/reports/suites/demo/functional.json")
	assertEqual(t, cfg.MarkdownPath, "/repo/reports/suites/demo/functional.md")
	assertEqual(t, cfg.WorkDir, "/repo/.bpfcompat")
	if cfg.Timeout != 8*time.Minute {
		t.Fatalf("unexpected timeout: %s", cfg.Timeout)
	}
	if cfg.Concurrency != 1 {
		t.Fatalf("unexpected concurrency: %d", cfg.Concurrency)
	}
	assertEqual(t, summary.ReportJSONPath, "/repo/reports/suites/demo/functional.json")
}

func TestRenderMarkdownIncludesCases(t *testing.T) {
	md := RenderMarkdown(Summary{
		Name:     "demo",
		Status:   "fail",
		ExitCode: 2,
		Cases: []CaseSummary{
			{Name: "one", Status: "pass", RequiredPassed: 1, TotalProfiles: 1, ReportMarkdownPath: "one.md"},
			{Name: "two", Status: "fail", RequiredFailed: 1, TotalProfiles: 1, ReportMarkdownPath: "two.md"},
		},
	})
	for _, want := range []string{"# bpfcompat Compatibility Suite", "`demo`", "`one`", "`two`", "0/1"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q:\n%s", want, md)
		}
	}
}

func assertEqual(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("unexpected value: got=%q want=%q", got, want)
	}
}
