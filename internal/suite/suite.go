package suite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/erenari/bpfcompat/internal/runner"
	"github.com/erenari/bpfcompat/pkg/schema"

	"gopkg.in/yaml.v3"
)

const (
	SchemaVersion = "bpfcompat_suite.v0.1"

	defaultTimeout     = 180 * time.Second
	defaultWorkDir     = ".bpfcompat"
	defaultReportDir   = "reports/suites"
	defaultRunner      = runner.RunnerVM
	defaultConcurrency = 2
)

var suiteNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Spec struct {
	Name     string   `yaml:"name"`
	Defaults Defaults `yaml:"defaults,omitempty"`
	Cases    []Case   `yaml:"cases"`
}

type Defaults struct {
	Matrix          string `yaml:"matrix,omitempty"`
	WorkDir         string `yaml:"workdir,omitempty"`
	ReportDir       string `yaml:"report_dir,omitempty"`
	Runner          string `yaml:"runner,omitempty"`
	Timeout         string `yaml:"timeout,omitempty"`
	Concurrency     int    `yaml:"concurrency,omitempty"`
	KeepVMOnFailure bool   `yaml:"keep_vm_on_failure,omitempty"`
}

type Case struct {
	Name            string `yaml:"name"`
	Artifact        string `yaml:"artifact"`
	ArtifactURI     string `yaml:"artifact_uri,omitempty"`
	ArtifactName    string `yaml:"artifact_name,omitempty"`
	ArtifactVersion string `yaml:"artifact_version,omitempty"`
	ArtifactVariant string `yaml:"artifact_variant,omitempty"`
	Matrix          string `yaml:"matrix,omitempty"`
	Manifest        string `yaml:"manifest,omitempty"`
	Out             string `yaml:"out,omitempty"`
	Markdown        string `yaml:"markdown,omitempty"`
	WorkDir         string `yaml:"workdir,omitempty"`
	Runner          string `yaml:"runner,omitempty"`
	Timeout         string `yaml:"timeout,omitempty"`
	Concurrency     int    `yaml:"concurrency,omitempty"`
	KeepVMOnFailure *bool  `yaml:"keep_vm_on_failure,omitempty"`
}

type RunOptions struct {
	SuitePath             string
	OutPath               string
	MarkdownPath          string
	WorkDir               string
	Timeout               time.Duration
	Concurrency           int
	StopOnFailure         bool
	UnsafeAllowHostRunner bool
}

type Summary struct {
	SchemaVersion string        `json:"schema_version"`
	Name          string        `json:"name"`
	StartedAt     string        `json:"started_at"`
	FinishedAt    string        `json:"finished_at"`
	DurationMS    int64         `json:"duration_ms"`
	Status        string        `json:"status"`
	ExitCode      int           `json:"exit_code"`
	Cases         []CaseSummary `json:"cases"`
}

type CaseSummary struct {
	Name               string `json:"name"`
	Artifact           string `json:"artifact"`
	Manifest           string `json:"manifest,omitempty"`
	Matrix             string `json:"matrix"`
	Status             string `json:"status"`
	ExitCode           int    `json:"exit_code"`
	Error              string `json:"error,omitempty"`
	RunID              string `json:"run_id,omitempty"`
	ReportJSONPath     string `json:"report_json_path,omitempty"`
	ReportMarkdownPath string `json:"report_markdown_path,omitempty"`
	TotalProfiles      int    `json:"total_profiles"`
	RequiredPassed     int    `json:"required_passed"`
	RequiredFailed     int    `json:"required_failed"`
}

func Load(path string) (Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Spec{}, fmt.Errorf("read suite file: %w", err)
	}
	return LoadBytes(data)
}

func LoadBytes(data []byte) (Spec, error) {
	var spec Spec
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&spec); err != nil {
		if !errors.Is(err, io.EOF) {
			return Spec{}, fmt.Errorf("parse suite YAML: %w", err)
		}
	}
	if err := Validate(spec); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

func Validate(spec Spec) error {
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		return errors.New("suite name is required")
	}
	if !suiteNamePattern.MatchString(name) {
		return fmt.Errorf("suite name %q must match %s", name, suiteNamePattern.String())
	}
	if len(spec.Cases) == 0 {
		return errors.New("suite must contain at least one case")
	}
	if spec.Defaults.Timeout != "" {
		if err := validateTimeout("defaults.timeout", spec.Defaults.Timeout); err != nil {
			return err
		}
	}
	if spec.Defaults.Concurrency < 0 {
		return errors.New("defaults.concurrency must be >= 0")
	}

	seen := make(map[string]struct{}, len(spec.Cases))
	for i := range spec.Cases {
		c := &spec.Cases[i]
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return fmt.Errorf("cases[%d].name is required", i)
		}
		if !suiteNamePattern.MatchString(name) {
			return fmt.Errorf("cases[%d].name %q must match %s", i, name, suiteNamePattern.String())
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate suite case %q", name)
		}
		seen[name] = struct{}{}

		if strings.TrimSpace(c.Artifact) == "" {
			return fmt.Errorf("cases[%d].artifact is required", i)
		}
		if strings.TrimSpace(c.Matrix) == "" && strings.TrimSpace(spec.Defaults.Matrix) == "" {
			return fmt.Errorf("cases[%d].matrix is required when defaults.matrix is unset", i)
		}
		if c.Timeout != "" {
			if err := validateTimeout(fmt.Sprintf("cases[%d].timeout", i), c.Timeout); err != nil {
				return err
			}
		}
		if c.Concurrency < 0 {
			return fmt.Errorf("cases[%d].concurrency must be >= 0", i)
		}
	}
	return nil
}

func Execute(ctx context.Context, opts RunOptions) (Summary, error) {
	if strings.TrimSpace(opts.SuitePath) == "" {
		return Summary{}, errors.New("--suite is required")
	}

	suitePath, err := filepath.Abs(opts.SuitePath)
	if err != nil {
		return Summary{}, fmt.Errorf("resolve suite path: %w", err)
	}
	spec, err := Load(suitePath)
	if err != nil {
		return Summary{}, err
	}

	started := time.Now().UTC()
	summary := Summary{
		SchemaVersion: SchemaVersion,
		Name:          strings.TrimSpace(spec.Name),
		StartedAt:     started.Format(time.RFC3339),
		Status:        "pass",
		ExitCode:      runner.ExitSuccess,
		Cases:         make([]CaseSummary, 0, len(spec.Cases)),
	}

	baseDir := filepath.Dir(suitePath)
caseLoop:
	for i := range spec.Cases {
		select {
		case <-ctx.Done():
			caseSummary := CaseSummary{
				Name:     spec.Cases[i].Name,
				Status:   "error",
				ExitCode: runner.ExitToolError,
				Error:    ctx.Err().Error(),
			}
			summary.Cases = append(summary.Cases, caseSummary)
			summary.Status = "error"
			summary.ExitCode = runner.ExitToolError
			break caseLoop
		default:
		}

		cfg, caseSummary, err := buildRunnerConfig(baseDir, spec, spec.Cases[i], opts)
		if err != nil {
			caseSummary.Status = "error"
			caseSummary.ExitCode = runner.ExitToolError
			caseSummary.Error = err.Error()
			summary.Cases = append(summary.Cases, caseSummary)
			updateSuiteStatus(&summary, caseSummary.ExitCode)
			if opts.StopOnFailure {
				break
			}
			continue
		}

		result, err := runner.ExecuteBootstrap(ctx, cfg)
		if err != nil {
			caseSummary.Status = "error"
			caseSummary.ExitCode = runner.ExitToolError
			caseSummary.Error = err.Error()
		} else {
			caseSummary = caseSummaryFromRun(caseSummary, result)
		}

		summary.Cases = append(summary.Cases, caseSummary)
		updateSuiteStatus(&summary, caseSummary.ExitCode)
		if opts.StopOnFailure && caseSummary.ExitCode != runner.ExitSuccess {
			break
		}
	}

	summary = finishSummary(summary, started)
	if opts.OutPath != "" {
		if err := WriteJSON(opts.OutPath, summary); err != nil {
			return Summary{}, err
		}
	}
	if opts.MarkdownPath != "" {
		if err := WriteMarkdown(opts.MarkdownPath, summary); err != nil {
			return Summary{}, err
		}
	}
	return summary, nil
}

func buildRunnerConfig(baseDir string, spec Spec, c Case, opts RunOptions) (runner.Config, CaseSummary, error) {
	reportDir := firstNonEmpty(spec.Defaults.ReportDir, defaultReportDir)
	reportDir = resolveSuitePath(baseDir, reportDir)

	caseName := strings.TrimSpace(c.Name)
	outPath := firstNonEmpty(c.Out, filepath.Join(reportDir, caseName+".json"))
	markdownPath := firstNonEmpty(c.Markdown, filepath.Join(reportDir, caseName+".md"))

	timeout, err := resolveTimeout(c.Timeout, spec.Defaults.Timeout, opts.Timeout)
	if err != nil {
		return runner.Config{}, CaseSummary{Name: caseName}, err
	}

	keepVMOnFailure := spec.Defaults.KeepVMOnFailure
	if c.KeepVMOnFailure != nil {
		keepVMOnFailure = *c.KeepVMOnFailure
	}

	cfg := runner.Config{
		ArtifactPath:          resolveSuitePath(baseDir, c.Artifact),
		ArtifactURI:           strings.TrimSpace(c.ArtifactURI),
		ArtifactName:          strings.TrimSpace(c.ArtifactName),
		ArtifactVersion:       strings.TrimSpace(c.ArtifactVersion),
		ArtifactVariant:       strings.TrimSpace(c.ArtifactVariant),
		MatrixPath:            resolveSuitePath(baseDir, firstNonEmpty(c.Matrix, spec.Defaults.Matrix)),
		ManifestPath:          resolveOptionalSuitePath(baseDir, c.Manifest),
		OutPath:               resolveSuitePath(baseDir, outPath),
		MarkdownPath:          resolveOptionalSuitePath(baseDir, markdownPath),
		WorkDir:               resolveSuitePath(baseDir, firstNonEmpty(opts.WorkDir, c.WorkDir, spec.Defaults.WorkDir, defaultWorkDir)),
		Runner:                firstNonEmpty(c.Runner, spec.Defaults.Runner, defaultRunner),
		Concurrency:           firstPositive(opts.Concurrency, c.Concurrency, spec.Defaults.Concurrency, defaultConcurrency),
		Timeout:               timeout,
		KeepVMOnFailure:       keepVMOnFailure,
		UnsafeAllowHostRunner: opts.UnsafeAllowHostRunner,
	}

	caseSummary := CaseSummary{
		Name:               caseName,
		Artifact:           cfg.ArtifactPath,
		Manifest:           cfg.ManifestPath,
		Matrix:             cfg.MatrixPath,
		ReportJSONPath:     cfg.OutPath,
		ReportMarkdownPath: cfg.MarkdownPath,
	}
	if err := cfg.Validate(); err != nil {
		return runner.Config{}, caseSummary, err
	}
	return cfg, caseSummary, nil
}

func caseSummaryFromRun(base CaseSummary, result runner.RunResult) CaseSummary {
	base.Status = result.Report.Summary.Status
	base.ExitCode = result.ExitCode
	base.RunID = result.Report.Run.ID
	base.ReportJSONPath = result.Report.Paths.JSON
	base.ReportMarkdownPath = result.Report.Paths.Markdown
	base.TotalProfiles = len(result.Report.Targets)
	base.RequiredPassed, base.RequiredFailed = requiredCounts(result.Report)
	return base
}

func requiredCounts(report schema.ReportV01) (int, int) {
	passed := 0
	failed := 0
	for i := range report.Targets {
		target := &report.Targets[i]
		if !target.Required {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(target.Status), "pass") {
			passed++
		} else {
			failed++
		}
	}
	return passed, failed
}

func updateSuiteStatus(summary *Summary, exitCode int) {
	switch {
	case exitCode == runner.ExitToolError:
		summary.Status = "error"
		summary.ExitCode = runner.ExitToolError
	case exitCode == runner.ExitCompatibilityFailure && summary.ExitCode != runner.ExitToolError:
		summary.Status = "fail"
		summary.ExitCode = runner.ExitCompatibilityFailure
	}
}

func finishSummary(summary Summary, started time.Time) Summary {
	finished := time.Now().UTC()
	summary.FinishedAt = finished.Format(time.RFC3339)
	summary.DurationMS = finished.Sub(started).Milliseconds()
	return summary
}

func WriteJSON(path string, summary Summary) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve suite JSON path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return fmt.Errorf("create suite JSON directory: %w", err)
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal suite JSON: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(absPath, data, 0o600); err != nil {
		return fmt.Errorf("write suite JSON: %w", err)
	}
	return nil
}

func WriteMarkdown(path string, summary Summary) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve suite Markdown path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return fmt.Errorf("create suite Markdown directory: %w", err)
	}
	if err := os.WriteFile(absPath, []byte(RenderMarkdown(summary)), 0o600); err != nil {
		return fmt.Errorf("write suite Markdown: %w", err)
	}
	return nil
}

func RenderMarkdown(summary Summary) string {
	var b strings.Builder
	b.WriteString("# bpfcompat Compatibility Suite\n\n")
	b.WriteString(fmt.Sprintf("- Suite: `%s`\n", markdownCell(summary.Name)))
	b.WriteString(fmt.Sprintf("- Status: `%s`\n", markdownCell(summary.Status)))
	b.WriteString(fmt.Sprintf("- Exit Code: `%d`\n", summary.ExitCode))
	b.WriteString(fmt.Sprintf("- Started: `%s`\n", markdownCell(summary.StartedAt)))
	if summary.FinishedAt != "" {
		b.WriteString(fmt.Sprintf("- Finished: `%s`\n", markdownCell(summary.FinishedAt)))
	}
	b.WriteString("\n## Cases\n\n")
	b.WriteString("| Case | Status | Required pass/fail | Profiles | Report |\n")
	b.WriteString("|---|---|---:|---:|---|\n")
	for i := range summary.Cases {
		c := &summary.Cases[i]
		reportPath := firstNonEmpty(c.ReportMarkdownPath, c.ReportJSONPath, "-")
		b.WriteString(fmt.Sprintf("| `%s` | `%s` | %d/%d | %d | `%s` |\n",
			markdownCell(c.Name),
			markdownCell(c.Status),
			c.RequiredPassed,
			c.RequiredFailed,
			c.TotalProfiles,
			markdownCell(reportPath),
		))
		if c.Error != "" {
			b.WriteString(fmt.Sprintf("| `%s` error |  |  |  | %s |\n", markdownCell(c.Name), markdownCell(c.Error)))
		}
	}
	return b.String()
}

func validateTimeout(label, raw string) error {
	timeout, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", label, err)
	}
	if timeout <= 0 {
		return fmt.Errorf("%s must be positive", label)
	}
	return nil
}

func resolveTimeout(caseRaw, defaultRaw string, override time.Duration) (time.Duration, error) {
	if override > 0 {
		return override, nil
	}
	for _, raw := range []string{caseRaw, defaultRaw} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		timeout, err := time.ParseDuration(raw)
		if err != nil {
			return 0, fmt.Errorf("parse timeout %q: %w", raw, err)
		}
		return timeout, nil
	}
	return defaultTimeout, nil
}

func resolveSuitePath(baseDir, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

func resolveOptionalSuitePath(baseDir, path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return resolveSuitePath(baseDir, path)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	return strings.ReplaceAll(value, "\n", " ")
}
