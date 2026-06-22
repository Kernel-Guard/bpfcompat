package manifest

import (
	"fmt"
	"strconv"
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

	seenMaps := make(map[string]struct{}, len(m.Maps))
	for i := range m.Maps {
		fixup := &m.Maps[i]
		if !validMapName(fixup.Name) {
			return fmt.Errorf("maps[%d].name %q must be a map identifier (letters, digits, '_', '.')", i, fixup.Name)
		}
		if _, exists := seenMaps[fixup.Name]; exists {
			return fmt.Errorf("duplicate map fixup %q", fixup.Name)
		}
		seenMaps[fixup.Name] = struct{}{}
		if fixup.MaxEntries == "" && fixup.InnerRingbufBytes == 0 && fixup.InnerMap == nil {
			return fmt.Errorf("map fixup %q must set max_entries, inner_ringbuf_bytes, or inner_map", fixup.Name)
		}
		if fixup.MaxEntries != "" && fixup.MaxEntries != "cpus" {
			entries, err := strconv.ParseUint(string(fixup.MaxEntries), 10, 32)
			if err != nil || entries == 0 {
				return fmt.Errorf("map fixup %q max_entries must be a positive integer or \"cpus\"", fixup.Name)
			}
		}
		if fixup.InnerMap != nil {
			if !innerMapTypes[fixup.InnerMap.Type] {
				return fmt.Errorf("map fixup %q inner_map.type %q must be one of hash, array, lru_hash, percpu_hash, percpu_array, lru_percpu_hash", fixup.Name, fixup.InnerMap.Type)
			}
			if fixup.InnerMap.ValueSize == 0 {
				return fmt.Errorf("map fixup %q inner_map.value_size must be positive", fixup.Name)
			}
			if fixup.InnerMap.MaxEntries == 0 {
				return fmt.Errorf("map fixup %q inner_map.max_entries must be positive", fixup.Name)
			}
		}
	}

	for i := range m.ProgramTypes {
		ov := &m.ProgramTypes[i]
		if strings.TrimSpace(ov.Program) == "" {
			return fmt.Errorf("program_types[%d].program is required (program name or ELF section)", i)
		}
		if !validProgramSelector(ov.Program) {
			return fmt.Errorf("program_types[%d].program %q must be a program name or ELF section (letters, digits, '_', '.', '/', '-')", i, ov.Program)
		}
		if !progTypeNames[ov.Type] {
			return fmt.Errorf("program_types[%d].type %q is not a recognized BPF program type", i, ov.Type)
		}
	}

	seenGroups := make(map[string]struct{}, len(m.ProgramVariants))
	seenVariantPrograms := make(map[string]struct{})
	for i := range m.ProgramVariants {
		group := &m.ProgramVariants[i]
		if !validMapName(group.Group) {
			return fmt.Errorf("program_variants[%d].group %q must be an identifier (letters, digits, '_', '.')", i, group.Group)
		}
		if _, exists := seenGroups[group.Group]; exists {
			return fmt.Errorf("duplicate program variant group %q", group.Group)
		}
		seenGroups[group.Group] = struct{}{}
		if len(group.Programs) == 0 {
			return fmt.Errorf("program variant group %q has no programs", group.Group)
		}
		for j := range group.Programs {
			variant := &group.Programs[j]
			if !validMapName(variant.Name) {
				return fmt.Errorf("program variant group %q programs[%d].name %q must be an identifier", group.Group, j, variant.Name)
			}
			if _, exists := seenVariantPrograms[variant.Name]; exists {
				return fmt.Errorf("program %q appears in more than one variant group", variant.Name)
			}
			seenVariantPrograms[variant.Name] = struct{}{}
			if variant.RequiresHelper != "" {
				if _, err := HelperID(variant.RequiresHelper); err != nil {
					return fmt.Errorf("program variant %q: %w", variant.Name, err)
				}
			}
			if variant.Probe != "" && variant.Probe != "trial_load" {
				return fmt.Errorf("program variant %q: probe must be \"trial_load\"", variant.Name)
			}
		}
	}

	seenCompanions := make(map[string]struct{}, len(m.ProbeCompanions))
	for i, companion := range m.ProbeCompanions {
		if !validMapName(companion) {
			return fmt.Errorf("probe_companions[%d] %q must be an identifier", i, companion)
		}
		if _, exists := seenCompanions[companion]; exists {
			return fmt.Errorf("duplicate probe companion %q", companion)
		}
		seenCompanions[companion] = struct{}{}
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

// validMapName restricts fixup names to BPF/ELF map identifiers so they are
// safe to interpolate into the validator command line inside the guest.
func validMapName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

// validProgramSelector accepts a program name or an ELF section name (which can
// contain '/' and '-'), while staying shell-safe for the validator CLI arg.
func validProgramSelector(sel string) bool {
	if sel == "" || len(sel) > 128 {
		return false
	}
	for _, r := range sel {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') &&
			r != '_' && r != '.' && r != '/' && r != '-' {
			return false
		}
	}
	return true
}
