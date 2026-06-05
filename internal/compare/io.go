package compare

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/erenari/bpfcompat/pkg/schema"
)

func LoadReport(path string) (schema.ReportV01, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return schema.ReportV01{}, fmt.Errorf("resolve report path %q: %w", path, err)
	}
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return schema.ReportV01{}, fmt.Errorf("read report JSON %q: %w", absPath, err)
	}
	var report schema.ReportV01
	if err := json.Unmarshal(raw, &report); err != nil {
		return schema.ReportV01{}, fmt.Errorf("parse report JSON %q: %w", absPath, err)
	}
	return report, nil
}

func LoadAndBuild(basePath, headPath string) (ReportDiff, error) {
	base, err := LoadReport(basePath)
	if err != nil {
		return ReportDiff{}, err
	}
	head, err := LoadReport(headPath)
	if err != nil {
		return ReportDiff{}, err
	}
	return Build(base, head, absOrOriginal(basePath), absOrOriginal(headPath), time.Now()), nil
}

func WriteJSON(outPath string, diff ReportDiff) error {
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("output path is required")
	}
	absPath, err := filepath.Abs(outPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	payload, err := json.MarshalIndent(diff, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal diff JSON: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(absPath, payload, 0o644); err != nil {
		return fmt.Errorf("write diff JSON: %w", err)
	}
	return nil
}

func WriteMarkdown(outPath string, diff ReportDiff) error {
	if strings.TrimSpace(outPath) == "" {
		return nil
	}
	absPath, err := filepath.Abs(outPath)
	if err != nil {
		return fmt.Errorf("resolve markdown output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return fmt.Errorf("create markdown output directory: %w", err)
	}

	var b strings.Builder
	b.WriteString("# bpfcompat Compatibility Diff\n\n")
	b.WriteString(fmt.Sprintf("- Base report: `%s`\n", diff.Base.Path))
	b.WriteString(fmt.Sprintf("- Head report: `%s`\n", diff.Head.Path))
	b.WriteString(fmt.Sprintf("- Generated at: `%s`\n", diff.GeneratedAt))
	b.WriteString(fmt.Sprintf("- Base status: `%s`\n", diff.Base.SummaryStatus))
	b.WriteString(fmt.Sprintf("- Head status: `%s`\n", diff.Head.SummaryStatus))
	b.WriteString("\n## Summary\n\n")
	b.WriteString(fmt.Sprintf("- Profiles: `%d`\n", diff.Summary.TotalProfiles))
	b.WriteString(fmt.Sprintf("- Changed: `%d`\n", diff.Summary.ChangedProfiles))
	b.WriteString(fmt.Sprintf("- Improved: `%d`\n", diff.Summary.ImprovedProfiles))
	b.WriteString(fmt.Sprintf("- Regressed: `%d`\n", diff.Summary.RegressedProfiles))
	b.WriteString(fmt.Sprintf("- Required regressions: `%d`\n", diff.Summary.RequiredRegressions))
	b.WriteString(fmt.Sprintf("- Required failures (base -> head): `%d` -> `%d`\n",
		diff.Summary.BaseRequiredFailed,
		diff.Summary.HeadRequiredFailed,
	))

	b.WriteString("\n## Profile Changes\n\n")
	b.WriteString("| Profile | Required | Change | Base | Head | Class Delta |\n")
	b.WriteString("|---|---:|---|---|---|---|\n")
	for _, profile := range diff.Profiles {
		b.WriteString(fmt.Sprintf("| `%s` | `%t` | `%s` | `%s` | `%s` | `%s` |\n",
			profile.ProfileID,
			profile.Required,
			emptyAsDash(profile.Change),
			emptyAsDash(profile.BaseStatus),
			emptyAsDash(profile.HeadStatus),
			emptyAsDash(profile.ClassificationDelta),
		))
	}

	if err := os.WriteFile(absPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write diff markdown: %w", err)
	}
	return nil
}

func absOrOriginal(path string) string {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absPath
}

func emptyAsDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}
