package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/erenari/bpfcompat/pkg/schema"
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
	b.WriteString(fmt.Sprintf("- Run ID: `%s`\n", report.Run.ID))
	b.WriteString(fmt.Sprintf("- Started At: `%s`\n", report.Run.StartedAt))
	b.WriteString(fmt.Sprintf("- Status: `%s`\n", report.Summary.Status))
	b.WriteString(fmt.Sprintf("- Artifact: `%s`\n", report.Artifact.Path))
	b.WriteString(fmt.Sprintf("- Artifact SHA-256: `%s`\n", report.Artifact.SHA256))
	b.WriteString(fmt.Sprintf("- Matrix: `%s`\n", report.Matrix.Path))
	b.WriteString(fmt.Sprintf("- Profiles: `%s`\n", strings.Join(report.Matrix.Profiles, ", ")))

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
			b.WriteString(fmt.Sprintf("| %s | `%s` | `%s` | `%s` | `%s` | `%t` | `%s` | `%s` | `%s` | `%s` | `%s` |\n",
				escapePipes(friendlyProfile(target.ProfileID)),
				escapePipes(formatTargetEnv(target.Profile)),
				escapePipes(hostKernel),
				target.Status,
				escapePipes(target.FailedStage),
				target.Required,
				escapePipes(btfStatus),
				escapePipes(formatFunctionalStatus(target.Functional)),
				escapePipes(target.ClassificationCode),
				escapePipes(target.ClassificationConfidence),
				escapePipes(target.InfraError),
			))
		}

		b.WriteString("\n## Target Details\n\n")
		for _, target := range report.Targets {
			b.WriteString(fmt.Sprintf("### %s\n\n", friendlyProfile(target.ProfileID)))
			b.WriteString(fmt.Sprintf("- Status: `%s`\n", target.Status))
			if target.Profile != nil {
				b.WriteString(fmt.Sprintf("- Profile Env: `%s`\n", formatTargetEnv(target.Profile)))
			}
			if target.Host != nil {
				b.WriteString(fmt.Sprintf("- Host Env: `%s`\n", formatTargetEnv(target.Host)))
			}
			if target.FailedStage != "" {
				b.WriteString(fmt.Sprintf("- Failed Stage: `%s`\n", target.FailedStage))
			}
			if target.Validation != nil {
				b.WriteString(fmt.Sprintf("- Load: `%s` (code=%d)\n", target.Validation.LoadStatus, target.Validation.LoadErrorCode))
				b.WriteString(fmt.Sprintf("- Attach: `%s` (mode=%s attempted=%d passed=%d failed=%d)\n",
					target.Validation.AttachStatus,
					target.Validation.AttachMode,
					target.Validation.AttachAttempted,
					target.Validation.AttachPassed,
					target.Validation.AttachFailed,
				))
			}
			if target.Functional != nil {
				b.WriteString(fmt.Sprintf("- Functional: `%s`\n", target.Functional.Status))
				for i := range target.Functional.Tests {
					test := &target.Functional.Tests[i]
					b.WriteString(fmt.Sprintf("  - `%s`: `%s` exit=%d expected=%d timeout=%ds required=%t\n",
						escapePipes(test.Name),
						escapePipes(test.Status),
						test.ExitCode,
						test.ExpectedExitCode,
						test.TimeoutSeconds,
						test.Required,
					))
					if test.Error != "" {
						b.WriteString(fmt.Sprintf("    - Error: %s\n", test.Error))
					}
				}
			}
			if target.ClassificationCode != "" {
				b.WriteString(fmt.Sprintf("- Classification: `%s` (`%s`)\n", target.ClassificationCode, target.ClassificationConfidence))
			}
			if target.ClassificationReason != "" {
				b.WriteString(fmt.Sprintf("- Reason: %s\n", target.ClassificationReason))
			}
			if target.ValidatorResult != "" {
				b.WriteString(fmt.Sprintf("- Validator Result: `%s`\n", target.ValidatorResult))
			}
			if target.SerialLog != "" {
				b.WriteString(fmt.Sprintf("- Serial Log: `%s`\n", target.SerialLog))
			}
			if len(target.Notes) > 0 {
				b.WriteString("- Notes:\n")
				for _, note := range target.Notes {
					b.WriteString(fmt.Sprintf("  - %s\n", note))
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
			b.WriteString(fmt.Sprintf("- %s\n", note))
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

func escapePipes(s string) string {
	if s == "" {
		return ""
	}
	return strings.ReplaceAll(s, "|", "\\|")
}

func friendlyProfile(id string) string {
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
		return "`" + id + "`"
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
