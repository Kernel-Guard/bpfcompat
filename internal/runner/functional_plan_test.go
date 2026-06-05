package runner

import (
	"os"
	"strings"
	"testing"

	"github.com/erenari/bpfcompat/internal/manifest"
)

func TestWriteFunctionalPlan(t *testing.T) {
	exitCode := 7
	required := false
	path, err := writeFunctionalPlan([]manifest.FunctionalTest{
		{
			Name:                 "capture-events",
			Command:              "sh -c 'printf event'",
			Required:             &required,
			Timeout:              "1500ms",
			ExpectExitCode:       &exitCode,
			ExpectStdoutContains: "event",
		},
	}, t.TempDir())
	if err != nil {
		t.Fatalf("write functional plan: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"functional_plan.v0.1\n",
		"BEGIN\n",
		"name=capture-events\n",
		"required=false\n",
		"timeout_seconds=2\n",
		"expect_exit_code=7\n",
		"expect_stdout_contains=event\n",
		"command=sh -c 'printf event'\n",
		"END\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plan missing %q:\n%s", want, text)
		}
	}
}

func TestFunctionalTimeoutSecondsDefault(t *testing.T) {
	got, err := functionalTimeoutSeconds("")
	if err != nil {
		t.Fatalf("default timeout: %v", err)
	}
	if got != 10 {
		t.Fatalf("default timeout got=%d want=10", got)
	}
}
