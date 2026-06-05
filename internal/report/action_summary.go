package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/erenari/bpfcompat/pkg/schema"
)

const (
	defaultActionSummaryMaxTargets  = 25
	defaultActionSummaryMaxFailures = 10
)

type ActionSummaryOptions struct {
	MaxTargets  int
	MaxFailures int
}

func BuildGitHubActionSummary(report schema.ReportV01, opts ActionSummaryOptions) string {
	if opts.MaxTargets <= 0 {
		opts.MaxTargets = defaultActionSummaryMaxTargets
	}
	if opts.MaxFailures <= 0 {
		opts.MaxFailures = defaultActionSummaryMaxFailures
	}

	counts := summarizeTargets(report.Targets)
	classes := summarizeFailureClasses(report.Targets)

	var b strings.Builder
	b.WriteString("# bpfcompat Compatibility Gate\n\n")
	b.WriteString(fmt.Sprintf("**Status:** `%s`\n\n", emptyAs(report.Summary.Status, "unknown")))
	b.WriteString("| Field | Value |\n")
	b.WriteString("|---|---|\n")
	b.WriteString(fmt.Sprintf("| Run ID | `%s` |\n", markdownTableCell(emptyAs(report.Run.ID, "-"))))
	b.WriteString(fmt.Sprintf("| Artifact | `%s` |\n", markdownTableCell(emptyAs(report.Artifact.BaseName, report.Artifact.Path))))
	b.WriteString(fmt.Sprintf("| Artifact SHA-256 | `%s` |\n", markdownTableCell(shortSHA(report.Artifact.SHA256))))
	b.WriteString(fmt.Sprintf("| Matrix | `%s` |\n", markdownTableCell(emptyAs(report.Matrix.Name, report.Matrix.Path))))
	b.WriteString(fmt.Sprintf("| Profiles | %d total, %d required |\n", counts.Total, counts.Required))
	b.WriteString(fmt.Sprintf("| Required pass/fail | %d/%d |\n", counts.RequiredPass, counts.RequiredFail))
	b.WriteString(fmt.Sprintf("| Optional pass/fail | %d/%d |\n", counts.OptionalPass, counts.OptionalFail))

	if len(classes) > 0 {
		b.WriteString("\n## Failure Classes\n\n")
		b.WriteString("| Class | Targets |\n")
		b.WriteString("|---|---:|\n")
		for _, class := range classes {
			b.WriteString(fmt.Sprintf("| `%s` | %d |\n", markdownTableCell(class.Code), class.Count))
		}
	}

	if len(report.Targets) > 0 {
		b.WriteString("\n## Compatibility Matrix\n\n")
		b.WriteString("| Profile | Required | Status | Kernel | BTF | Functional | Class |\n")
		b.WriteString("|---|---:|---|---|---|---|---|\n")
		targets := report.Targets
		limit := opts.MaxTargets
		if len(targets) < limit {
			limit = len(targets)
		}
		for i := 0; i < limit; i++ {
			target := &targets[i]
			b.WriteString(fmt.Sprintf("| %s | %t | `%s` | `%s` | `%s` | `%s` | `%s` |\n",
				markdownTableCell(target.ProfileID),
				target.Required,
				markdownTableCell(emptyAs(target.Status, "unknown")),
				markdownTableCell(targetKernel(target)),
				markdownTableCell(targetBTF(target)),
				markdownTableCell(targetFunctional(target)),
				markdownTableCell(emptyAs(target.ClassificationCode, "-")),
			))
		}
		if len(targets) > limit {
			b.WriteString(fmt.Sprintf("\n_Showing %d of %d profiles. Download the JSON/Markdown artifacts for full target logs._\n", limit, len(targets)))
		}
	}

	failures := failingTargets(report.Targets)
	if len(failures) > 0 {
		b.WriteString("\n## Failure Details\n\n")
		limit := opts.MaxFailures
		if len(failures) < limit {
			limit = len(failures)
		}
		for i := 0; i < limit; i++ {
			target := failures[i]
			reason := firstNonEmpty(target.ClassificationReason, target.InfraError, target.FailedStage, "validation failed")
			class := emptyAs(target.ClassificationCode, "UNCLASSIFIED_FAILURE")
			b.WriteString(fmt.Sprintf("- `%s`: `%s` - %s\n", target.ProfileID, class, sanitizeMarkdownText(reason)))
		}
		if len(failures) > limit {
			b.WriteString(fmt.Sprintf("- ... %d more failing target(s). See the full report artifact.\n", len(failures)-limit))
		}

		hints := remediationHints(failures)
		if len(hints) > 0 {
			b.WriteString("\n## Suggested Next Steps\n\n")
			for _, hint := range hints {
				b.WriteString(fmt.Sprintf("- %s\n", hint))
			}
		}
	}

	if len(report.Summary.Notes) > 0 {
		b.WriteString("\n## Report Notes\n\n")
		for _, note := range report.Summary.Notes {
			b.WriteString(fmt.Sprintf("- %s\n", sanitizeMarkdownText(note)))
		}
	}

	return b.String()
}

type targetCounts struct {
	Total        int
	Required     int
	RequiredPass int
	RequiredFail int
	OptionalPass int
	OptionalFail int
}

func summarizeTargets(targets []schema.Target) targetCounts {
	var counts targetCounts
	counts.Total = len(targets)
	for i := range targets {
		target := &targets[i]
		pass := strings.EqualFold(strings.TrimSpace(target.Status), "pass")
		if target.Required {
			counts.Required++
			if pass {
				counts.RequiredPass++
			} else {
				counts.RequiredFail++
			}
			continue
		}
		if pass {
			counts.OptionalPass++
		} else {
			counts.OptionalFail++
		}
	}
	return counts
}

type failureClassCount struct {
	Code  string
	Count int
}

func summarizeFailureClasses(targets []schema.Target) []failureClassCount {
	counts := make(map[string]int)
	for i := range targets {
		target := &targets[i]
		if strings.EqualFold(strings.TrimSpace(target.Status), "pass") {
			continue
		}
		code := strings.TrimSpace(target.ClassificationCode)
		if code == "" {
			if strings.TrimSpace(target.InfraError) != "" {
				code = "INFRA_ERROR"
			} else {
				code = "UNCLASSIFIED_FAILURE"
			}
		}
		counts[code]++
	}

	classes := make([]failureClassCount, 0, len(counts))
	for code, count := range counts {
		classes = append(classes, failureClassCount{Code: code, Count: count})
	}
	sort.Slice(classes, func(i, j int) bool {
		if classes[i].Count != classes[j].Count {
			return classes[i].Count > classes[j].Count
		}
		return classes[i].Code < classes[j].Code
	})
	return classes
}

func failingTargets(targets []schema.Target) []*schema.Target {
	failures := make([]*schema.Target, 0)
	for i := range targets {
		target := &targets[i]
		if !strings.EqualFold(strings.TrimSpace(target.Status), "pass") {
			failures = append(failures, target)
		}
	}
	return failures
}

func remediationHints(failures []*schema.Target) []string {
	seenClasses := make(map[string]bool)
	for i := range failures {
		target := failures[i]
		code := strings.TrimSpace(target.ClassificationCode)
		if code != "" {
			seenClasses[code] = true
		}
	}

	hintByClass := map[string]string{
		"MISSING_BTF":              "`MISSING_BTF`: use a non-CO-RE fallback, provide external BTF, or remove CO-RE dependency for that kernel band.",
		"CORE_RELOCATION_FAILURE":  "`CORE_RELOCATION_FAILURE`: validate against the target BTF layout and ship a profile-specific variant when field layouts diverge.",
		"UNSUPPORTED_PROGRAM_TYPE": "`UNSUPPORTED_PROGRAM_TYPE`: ship an older-kernel-compatible variant, for example avoid fentry/fexit on kernels before 5.5.",
		"UNSUPPORTED_MAP_TYPE":     "`UNSUPPORTED_MAP_TYPE`: use a map-compatible fallback for older kernels, for example perfbuf instead of ringbuf where needed.",
		"UNSUPPORTED_ATTACH_TYPE":  "`UNSUPPORTED_ATTACH_TYPE`: change the hook/attach strategy for that kernel or make attach optional in the manifest.",
		"POLICY_DENIED":            "`POLICY_DENIED`: check kernel lockdown, unprivileged BPF, capabilities, and runner security policy.",
		"CAPABILITY_FAILURE":       "`CAPABILITY_FAILURE`: compare the failed helper/map/program capability against the target profile and select a compatible variant.",
		"VERIFIER_REJECTION":       "`VERIFIER_REJECTION`: inspect the validator/libbpf logs from the uploaded report artifact.",
		"FUNCTIONAL_TEST_FAILURE":  "`FUNCTIONAL_TEST_FAILURE`: inspect the functional command output and project-specific test assets; the artifact loaded but did not satisfy the integration test.",
	}

	keys := make([]string, 0, len(seenClasses))
	for key := range seenClasses {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	hints := make([]string, 0, len(keys))
	for _, key := range keys {
		if hint := hintByClass[key]; hint != "" {
			hints = append(hints, hint)
		}
	}
	return hints
}

func targetKernel(target *schema.Target) string {
	if target.Host != nil && strings.TrimSpace(target.Host.Kernel) != "" {
		return target.Host.Kernel
	}
	if target.Profile != nil && strings.TrimSpace(target.Profile.Kernel) != "" {
		return target.Profile.Kernel
	}
	return "-"
}

func targetBTF(target *schema.Target) string {
	if target.BTF == nil {
		return "-"
	}
	if target.BTF.KernelBTFAvailable {
		return "kernel:yes"
	}
	return "kernel:no"
}

func targetFunctional(target *schema.Target) string {
	if target == nil || target.Functional == nil || target.Functional.Status == "" {
		return "-"
	}
	return target.Functional.Status
}

func shortSHA(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 12 {
		return emptyAs(value, "-")
	}
	return value[:12]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func emptyAs(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func markdownTableCell(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "|", "\\|")
	return value
}

func sanitizeMarkdownText(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}
