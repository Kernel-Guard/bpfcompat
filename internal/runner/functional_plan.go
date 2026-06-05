package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/erenari/bpfcompat/internal/manifest"
)

const functionalPlanVersion = "functional_plan.v0.1"

func writeFunctionalPlan(tests []manifest.FunctionalTest, dir string) (string, error) {
	if len(tests) == 0 {
		return "", nil
	}
	if len(tests) > 32 {
		return "", fmt.Errorf("too many functional tests: max 32")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create functional plan directory: %w", err)
	}

	path := filepath.Join(dir, "functional-plan.txt")
	var b strings.Builder
	b.WriteString(functionalPlanVersion)
	b.WriteByte('\n')
	for i := range tests {
		test := &tests[i]
		required := true
		if test.Required != nil {
			required = *test.Required
		}
		expectedExit := 0
		if test.ExpectExitCode != nil {
			expectedExit = *test.ExpectExitCode
		}
		timeoutSeconds, err := functionalTimeoutSeconds(test.Timeout)
		if err != nil {
			return "", fmt.Errorf("functional test %q timeout: %w", test.Name, err)
		}

		b.WriteString("BEGIN\n")
		writePlanKV(&b, "name", test.Name)
		writePlanKV(&b, "required", strconv.FormatBool(required))
		writePlanKV(&b, "timeout_seconds", strconv.Itoa(timeoutSeconds))
		writePlanKV(&b, "expect_exit_code", strconv.Itoa(expectedExit))
		writePlanKV(&b, "expect_stdout_contains", test.ExpectStdoutContains)
		writePlanKV(&b, "expect_stderr_contains", test.ExpectStderrContains)
		writePlanKV(&b, "command", test.Command)
		b.WriteString("END\n")
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("write functional plan: %w", err)
	}
	return path, nil
}

func functionalTimeoutSeconds(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 10, nil
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("must be positive")
	}
	seconds := int((timeout + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return seconds, nil
}

func writePlanKV(b *strings.Builder, key, value string) {
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(strings.TrimSpace(value))
	b.WriteByte('\n')
}
