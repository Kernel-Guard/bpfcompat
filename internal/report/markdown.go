package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

func WriteMarkdown(outPath string, report schema.ReportV01) error {
	if outPath == "" {
		return nil
	}

	absOut, err := filepath.Abs(outPath)
	if err != nil {
		return fmt.Errorf("resolve Markdown output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absOut), 0o755); err != nil {
		return fmt.Errorf("create Markdown directory: %w", err)
	}

	var b strings.Builder
	b.WriteString("# bpfcompat Compatibility Report\n\n")
	fmt.Fprintf(&b, "- Run ID: %s\n", markdownCode(report.Run.ID))
	fmt.Fprintf(&b, "- Started At: %s\n", markdownCode(report.Run.StartedAt))
	fmt.Fprintf(&b, "- Status: %s\n", markdownCode(report.Summary.Status))
	if report.Summary.Verdict != "" {
		fmt.Fprintf(&b, "- Verdict: %s\n", markdownCode(report.Summary.Verdict))
	}
	// Incomplete coverage has to be visible in the rendered report too: a
	// COMPATIBLE verdict over a matrix where some target never answered is a
	// weaker claim than it looks, and the Markdown is what people read first.
	if report.Summary.Complete != nil && !*report.Summary.Complete {
		b.WriteString("- Coverage: `incomplete` (at least one target produced no compatibility answer)\n")
	}
	fmt.Fprintf(&b, "- Artifact: %s\n", markdownCode(report.Artifact.Path))
	if report.Artifact.Source != "" {
		fmt.Fprintf(&b, "- Artifact Source: %s\n", markdownCode(report.Artifact.Source))
	}
	if report.Artifact.SourceDigest != "" {
		fmt.Fprintf(&b, "- Artifact Source Digest: %s\n", markdownCode(report.Artifact.SourceDigest))
	}
	fmt.Fprintf(&b, "- Artifact SHA-256: %s\n", markdownCode(report.Artifact.SHA256))
	if report.Validator != nil {
		fmt.Fprintf(&b, "- Validator: %s\n", markdownCode(report.Validator.BaseName))
		fmt.Fprintf(&b, "- Validator SHA-256: %s\n", markdownCode(report.Validator.SHA256))
	}
	if report.Command != nil {
		fmt.Fprintf(&b, "- Command invocation SHA-256: %s\n", markdownCode(report.Command.InvocationSHA256))
		b.WriteString(fmt.Sprintf("- Command expected exit code: `%d`\n", report.Command.ExpectedExitCode))
		if report.Command.Binary != nil {
			fmt.Fprintf(&b, "- Command binary: %s\n", markdownCode(report.Command.Binary.BaseName))
			fmt.Fprintf(&b, "- Command binary SHA-256: %s\n", markdownCode(report.Command.Binary.SHA256))
		}
	}
	fmt.Fprintf(&b, "- Matrix: %s\n", markdownCode(report.Matrix.Path))
	fmt.Fprintf(&b, "- Profiles: %s\n", markdownCode(strings.Join(report.Matrix.Profiles, ", ")))

	if len(report.Targets) > 0 {
		b.WriteString("\n## Targets\n\n")
		b.WriteString("| Profile | Profile Env | Host Kernel | Status | Failed Stage | Required | BTF | Functional | Classification | Confidence | Infra Error |\n")
		b.WriteString("|---|---|---|---|---|---:|---|---|---|---|---|\n")
		for _, target := range report.Targets {
			btfStatus := ""
			if target.BTF != nil {
				if target.BTF.KernelBTFAvailable {
					btfStatus = "kernel_btf:yes"
				} else {
					btfStatus = "kernel_btf:no"
				}
			}
			hostKernel := "-"
			if target.Host != nil && target.Host.Kernel != "" {
				hostKernel = target.Host.Kernel
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | `%t` | %s | %s | %s | %s | %s |\n",
				friendlyProfile(target.ProfileID, markdownTableCode),
				markdownTableCode(formatTargetEnv(target.Profile)),
				markdownTableCode(hostKernel),
				markdownTableCode(target.Status),
				markdownTableCode(target.FailedStage),
				target.Required,
				markdownTableCode(btfStatus),
				markdownTableCode(formatFunctionalStatus(target.Functional)),
				markdownTableCode(target.ClassificationCode),
				markdownTableCode(target.ClassificationConfidence),
				markdownTableCode(target.InfraError),
			)
		}

		b.WriteString("\n## Target Details\n\n")
		for _, target := range report.Targets {
			fmt.Fprintf(&b, "### %s\n\n", friendlyProfile(target.ProfileID, markdownCode))
			fmt.Fprintf(&b, "- Status: %s\n", markdownCode(target.Status))
			if target.Profile != nil {
				fmt.Fprintf(&b, "- Profile Env: %s\n", markdownCode(formatTargetEnv(target.Profile)))
			}
			if target.Host != nil {
				fmt.Fprintf(&b, "- Host Env: %s\n", markdownCode(formatTargetEnv(target.Host)))
			}
			if target.FailedStage != "" {
				fmt.Fprintf(&b, "- Failed Stage: %s\n", markdownCode(target.FailedStage))
			}
			if target.Validation != nil {
				fmt.Fprintf(&b, "- Load: %s (code=%d)\n", markdownCode(target.Validation.LoadStatus), target.Validation.LoadErrorCode)
				fmt.Fprintf(&b, "- Attach: %s (mode=%s attempted=%d passed=%d failed=%d)\n",
					markdownCode(target.Validation.AttachStatus),
					markdownInline(target.Validation.AttachMode),
					target.Validation.AttachAttempted,
					target.Validation.AttachPassed,
					target.Validation.AttachFailed,
				)
			}
			if target.Functional != nil {
				fmt.Fprintf(&b, "- Functional: %s\n", markdownCode(target.Functional.Status))
				for i := range target.Functional.Tests {
					test := &target.Functional.Tests[i]
					fmt.Fprintf(&b, "  - %s: %s exit=%d expected=%d timeout=%ds required=%t\n",
						markdownCode(test.Name),
						markdownCode(test.Status),
						test.ExitCode,
						test.ExpectedExitCode,
						test.TimeoutSeconds,
						test.Required,
					)
					if test.Error != "" {
						fmt.Fprintf(&b, "    - Error: %s\n", markdownInline(test.Error))
					}
				}
			}
			if target.ClassificationCode != "" {
				fmt.Fprintf(&b, "- Classification: %s (%s)\n", markdownCode(target.ClassificationCode), markdownCode(target.ClassificationConfidence))
			}
			if target.ClassificationReason != "" {
				fmt.Fprintf(&b, "- Reason: %s\n", markdownInline(target.ClassificationReason))
			}
			if target.ValidatorResult != "" {
				fmt.Fprintf(&b, "- Validator Result: %s\n", markdownCode(target.ValidatorResult))
			}
			if target.SerialLog != "" {
				fmt.Fprintf(&b, "- Serial Log: %s\n", markdownCode(target.SerialLog))
			}
			if len(target.Notes) > 0 {
				b.WriteString("- Notes:\n")
				for _, note := range target.Notes {
					fmt.Fprintf(&b, "  - %s\n", markdownInline(note))
				}
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\n## Notes\n\n")
	if len(report.Summary.Notes) == 0 {
		b.WriteString("- None\n")
	} else {
		for _, note := range report.Summary.Notes {
			fmt.Fprintf(&b, "- %s\n", markdownInline(note))
		}
	}

	return os.WriteFile(absOut, []byte(b.String()), 0o644)
}

func formatFunctionalStatus(functional *schema.Functional) string {
	if functional == nil || functional.Status == "" {
		return "-"
	}
	return functional.Status
}

// friendlyProfile names a profile for a heading or table cell. Known profile
// IDs get a fixed label; any other ID is rendered with code, which is
// markdownCode or markdownTableCode depending on where it lands.
func friendlyProfile(id string, code func(string) string) string {
	switch id {
	case "ubuntu-18.04-4.15":
		return "Ubuntu 18.04 (4.15) [`ubuntu-18.04-4.15`]"
	case "ubuntu-20.04-5.4":
		return "Ubuntu 20.04 (5.4) [`ubuntu-20.04-5.4`]"
	case "ubuntu-22.04-5.15":
		return "Ubuntu 22.04 (5.15) [`ubuntu-22.04-5.15`]"
	case "debian-12-6.1":
		return "Debian 12 (6.1) [`debian-12-6.1`]"
	default:
		return code(id)
	}
}

func formatTargetEnv(env *schema.TargetEnv) string {
	if env == nil {
		return "-"
	}
	parts := make([]string, 0, 5)
	if env.Distro != "" {
		parts = append(parts, env.Distro)
	}
	if env.Version != "" {
		parts = append(parts, env.Version)
	}
	if env.KernelFamily != "" {
		parts = append(parts, "kfamily="+env.KernelFamily)
	}
	if env.Kernel != "" {
		parts = append(parts, "kernel="+env.Kernel)
	}
	if env.Arch != "" {
		parts = append(parts, "arch="+env.Arch)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}
