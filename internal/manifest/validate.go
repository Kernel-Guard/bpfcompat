package manifest

import (
	"fmt"
	"strings"
	"time"
)

var allowedAttachKinds = map[string]struct{}{
	"":               {},
	"tracepoint":     {},
	"raw_tracepoint": {},
	"kprobe":         {},
	"kretprobe":      {},
	"fentry":         {},
	"fexit":          {},
	"xdp":            {},
	"tc":             {},
	"cgroup":         {},
	"lsm":            {},
	"uprobe":         {},
}

func Validate(m Manifest) error {
	seenPrograms := make(map[string]struct{}, len(m.Programs))
	for i, program := range m.Programs {
		if program.Name == "" {
			return fmt.Errorf("programs[%d].name is required", i)
		}
		if _, exists := seenPrograms[program.Name]; exists {
			return fmt.Errorf("duplicate program name %q", program.Name)
		}
		seenPrograms[program.Name] = struct{}{}

		if _, ok := allowedAttachKinds[program.Attach.Kind]; !ok {
			return fmt.Errorf("program %q has unsupported attach kind %q", program.Name, program.Attach.Kind)
		}
	}

	seenProfiles := make(map[string]struct{}, len(m.RequiredProfiles))
	for _, profile := range m.RequiredProfiles {
		if profile == "" {
			return fmt.Errorf("required_profiles contains empty value")
		}
		if _, exists := seenProfiles[profile]; exists {
			return fmt.Errorf("duplicate required profile %q", profile)
		}
		seenProfiles[profile] = struct{}{}
	}

	seenFunctionalTests := make(map[string]struct{}, len(m.FunctionalTests))
	for i := range m.FunctionalTests {
		test := &m.FunctionalTests[i]
		if strings.TrimSpace(test.Name) == "" {
			return fmt.Errorf("functional_tests[%d].name is required", i)
		}
		if hasLineBreak(test.Name) {
			return fmt.Errorf("functional_tests[%d].name must be single-line", i)
		}
		if _, exists := seenFunctionalTests[test.Name]; exists {
			return fmt.Errorf("duplicate functional test %q", test.Name)
		}
		seenFunctionalTests[test.Name] = struct{}{}

		if strings.TrimSpace(test.Command) == "" {
			return fmt.Errorf("functional_tests[%d].command is required", i)
		}
		if hasLineBreak(test.Command) {
			return fmt.Errorf("functional_tests[%d].command must be single-line", i)
		}
		if len(test.Command) > 1000 {
			return fmt.Errorf("functional_tests[%d].command is too long", i)
		}
		if hasLineBreak(test.ExpectStdoutContains) || hasLineBreak(test.ExpectStderrContains) {
			return fmt.Errorf("functional_tests[%d] expectations must be single-line", i)
		}

		if strings.TrimSpace(test.Timeout) != "" {
			timeout, err := time.ParseDuration(test.Timeout)
			if err != nil {
				return fmt.Errorf("functional_tests[%d].timeout is invalid: %w", i, err)
			}
			if timeout <= 0 {
				return fmt.Errorf("functional_tests[%d].timeout must be positive", i)
			}
			if timeout > 5*time.Minute {
				return fmt.Errorf("functional_tests[%d].timeout must be <= 5m", i)
			}
		}
		if test.ExpectExitCode != nil && (*test.ExpectExitCode < 0 || *test.ExpectExitCode > 255) {
			return fmt.Errorf("functional_tests[%d].expect_exit_code must be between 0 and 255", i)
		}
	}

	return nil
}

func hasLineBreak(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}
