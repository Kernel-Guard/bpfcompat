package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/erenari/bpfcompat/internal/manifest"
	"github.com/erenari/bpfcompat/internal/registry"
	"github.com/erenari/bpfcompat/internal/runtime"
	"gopkg.in/yaml.v3"
)

type runtimeExecuteGuardPolicy struct {
	SchemaVersion string                    `json:"schema_version" yaml:"schema_version"`
	DefaultAction string                    `json:"default_action" yaml:"default_action"`
	Rules         []runtimeExecuteGuardRule `json:"rules" yaml:"rules"`
}

type runtimeExecuteGuardRule struct {
	Name                   string   `json:"name" yaml:"name"`
	Action                 string   `json:"action" yaml:"action"`
	Tenants                []string `json:"tenants,omitempty" yaml:"tenants,omitempty"`
	Projects               []string `json:"projects,omitempty" yaml:"projects,omitempty"`
	Artifacts              []string `json:"artifacts,omitempty" yaml:"artifacts,omitempty"`
	Profiles               []string `json:"profiles,omitempty" yaml:"profiles,omitempty"`
	ProgramTypes           []string `json:"program_types,omitempty" yaml:"program_types,omitempty"`
	AttachKinds            []string `json:"attach_kinds,omitempty" yaml:"attach_kinds,omitempty"`
	KernelMin              string   `json:"kernel_min,omitempty" yaml:"kernel_min,omitempty"`
	KernelMax              string   `json:"kernel_max,omitempty" yaml:"kernel_max,omitempty"`
	RequireVerifiedHistory *bool    `json:"require_verified_history,omitempty" yaml:"require_verified_history,omitempty"`
}

type runtimeExecuteGuardContext struct {
	Tenant          string
	Project         string
	ArtifactName    string
	TargetProfileID string
	SelectedRecord  registry.ArtifactVersionRecord
	HostProbe       *runtime.HostCapabilities
	HistoryVerified bool
	Manifest        *manifest.Manifest
}

type runtimeExecuteGuardDecision struct {
	Allowed  bool
	RuleName string
	Action   string
	Reason   string
}

func loadRuntimeExecuteGuardPolicyFromEnv() (*runtimeExecuteGuardPolicy, error) {
	path := runtimeExecutePolicyPath()
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read runtime execute policy: %w", err)
	}

	var policy runtimeExecuteGuardPolicy
	if strings.HasSuffix(strings.ToLower(path), ".yaml") || strings.HasSuffix(strings.ToLower(path), ".yml") {
		decoder := yaml.NewDecoder(bytes.NewReader(raw))
		decoder.KnownFields(true)
		if err := decoder.Decode(&policy); err != nil {
			return nil, fmt.Errorf("parse runtime execute policy YAML: %w", err)
		}
	} else {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&policy); err != nil {
			return nil, fmt.Errorf("parse runtime execute policy JSON: %w", err)
		}
	}
	if err := policy.normalizeAndValidate(); err != nil {
		return nil, err
	}
	return &policy, nil
}

func runtimeExecutePolicyPath() string {
	return strings.TrimSpace(os.Getenv(envRuntimeExecPolicyPath))
}

func runtimeExecutePolicyRequired() bool {
	return parseBoolEnv(envRuntimeExecRequirePolicy, false)
}

func (p *runtimeExecuteGuardPolicy) normalizeAndValidate() error {
	p.DefaultAction = normalizePolicyAction(p.DefaultAction)
	if p.DefaultAction == "" {
		p.DefaultAction = "allow"
	}
	if !isPolicyAction(p.DefaultAction) {
		return fmt.Errorf("runtime execute policy default_action must be allow or deny")
	}

	for i := range p.Rules {
		r := &p.Rules[i]
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" {
			r.Name = fmt.Sprintf("rule-%d", i+1)
		}
		r.Action = normalizePolicyAction(r.Action)
		if !isPolicyAction(r.Action) {
			return fmt.Errorf("runtime execute policy rule %q action must be allow or deny", r.Name)
		}
		r.Tenants = normalizeLowerList(r.Tenants)
		r.Projects = normalizeLowerList(r.Projects)
		r.Artifacts = normalizeLowerList(r.Artifacts)
		r.Profiles = normalizeLowerList(r.Profiles)
		r.ProgramTypes = normalizeUpperList(r.ProgramTypes)
		r.AttachKinds = normalizeUpperList(r.AttachKinds)
		r.KernelMin = strings.TrimSpace(r.KernelMin)
		r.KernelMax = strings.TrimSpace(r.KernelMax)
		if r.KernelMin != "" {
			if _, err := parseKernelVersion(r.KernelMin); err != nil {
				return fmt.Errorf("runtime execute policy rule %q invalid kernel_min %q: %w", r.Name, r.KernelMin, err)
			}
		}
		if r.KernelMax != "" {
			if _, err := parseKernelVersion(r.KernelMax); err != nil {
				return fmt.Errorf("runtime execute policy rule %q invalid kernel_max %q: %w", r.Name, r.KernelMax, err)
			}
		}
	}
	return nil
}

func evaluateRuntimeExecuteGuardPolicy(policy runtimeExecuteGuardPolicy, ctx runtimeExecuteGuardContext) runtimeExecuteGuardDecision {
	defaultAction := normalizePolicyAction(policy.DefaultAction)
	if defaultAction == "" {
		defaultAction = "allow"
	}
	for _, rule := range policy.Rules {
		if !runtimeExecuteRuleMatches(rule, ctx) {
			continue
		}
		decision := runtimeExecuteGuardDecision{
			Allowed:  rule.Action == "allow",
			RuleName: rule.Name,
			Action:   rule.Action,
			Reason:   fmt.Sprintf("matched policy rule %q", rule.Name),
		}
		return decision
	}

	decision := runtimeExecuteGuardDecision{
		Allowed:  defaultAction == "allow",
		RuleName: "default",
		Action:   defaultAction,
		Reason:   "no policy rule matched; default_action applied",
	}
	return decision
}

func runtimeExecutePolicyNeedsHostProbe(policy runtimeExecuteGuardPolicy, targetProfile string) bool {
	targetProfile = strings.TrimSpace(targetProfile)
	for _, rule := range policy.Rules {
		if strings.TrimSpace(rule.KernelMin) != "" || strings.TrimSpace(rule.KernelMax) != "" {
			return true
		}
		if targetProfile == "" && len(rule.Profiles) > 0 {
			return true
		}
	}
	return false
}

func runtimeExecutePolicyNeedsManifest(policy runtimeExecuteGuardPolicy) bool {
	for _, rule := range policy.Rules {
		if len(rule.ProgramTypes) > 0 || len(rule.AttachKinds) > 0 {
			return true
		}
	}
	return false
}

func runtimeExecuteRuleMatches(rule runtimeExecuteGuardRule, ctx runtimeExecuteGuardContext) bool {
	tenant := strings.ToLower(strings.TrimSpace(ctx.Tenant))
	project := strings.ToLower(strings.TrimSpace(ctx.Project))
	artifactName := strings.ToLower(strings.TrimSpace(ctx.ArtifactName))
	if !matchStringPatterns(tenant, rule.Tenants) {
		return false
	}
	if !matchStringPatterns(project, rule.Projects) {
		return false
	}
	if !matchStringPatterns(artifactName, rule.Artifacts) {
		return false
	}
	if rule.RequireVerifiedHistory != nil && *rule.RequireVerifiedHistory != ctx.HistoryVerified {
		return false
	}

	if len(rule.Profiles) > 0 {
		candidates := runtimeExecuteProfileCandidates(ctx)
		if !matchAnyPattern(candidates, rule.Profiles) {
			return false
		}
	}

	if strings.TrimSpace(rule.KernelMin) != "" || strings.TrimSpace(rule.KernelMax) != "" {
		if ctx.HostProbe == nil {
			return false
		}
		hostVersion, err := parseKernelVersion(ctx.HostProbe.Kernel.Release)
		if err != nil {
			return false
		}
		if strings.TrimSpace(rule.KernelMin) != "" {
			minVersion, _ := parseKernelVersion(rule.KernelMin)
			if compareKernelVersion(hostVersion, minVersion) < 0 {
				return false
			}
		}
		if strings.TrimSpace(rule.KernelMax) != "" {
			maxVersion, _ := parseKernelVersion(rule.KernelMax)
			if compareKernelVersion(hostVersion, maxVersion) > 0 {
				return false
			}
		}
	}

	if len(rule.ProgramTypes) > 0 {
		if ctx.Manifest == nil {
			return false
		}
		found := false
		for _, program := range ctx.Manifest.Programs {
			programType := strings.ToUpper(strings.TrimSpace(program.Type))
			if programType == "" {
				continue
			}
			if matchStringPatterns(programType, rule.ProgramTypes) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(rule.AttachKinds) > 0 {
		if ctx.Manifest == nil {
			return false
		}
		found := false
		for _, program := range ctx.Manifest.Programs {
			attachKind := strings.ToUpper(strings.TrimSpace(program.Attach.Kind))
			if attachKind == "" {
				continue
			}
			if matchStringPatterns(attachKind, rule.AttachKinds) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func runtimeExecuteProfileCandidates(ctx runtimeExecuteGuardContext) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 4+len(ctx.SelectedRecord.SupportedProfiles))
	appendUnique := func(value string) {
		v := strings.ToLower(strings.TrimSpace(value))
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	appendUnique(ctx.TargetProfileID)
	for _, profile := range ctx.SelectedRecord.SupportedProfiles {
		appendUnique(profile)
	}
	if ctx.HostProbe != nil {
		appendUnique(runtime.HostProfileHint(*ctx.HostProbe))
	}
	return out
}

func normalizePolicyAction(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isPolicyAction(value string) bool {
	switch value {
	case "allow", "deny":
		return true
	default:
		return false
	}
}

func normalizeLowerList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		clean := strings.ToLower(strings.TrimSpace(value))
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

func normalizeUpperList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		clean := strings.ToUpper(strings.TrimSpace(value))
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

func matchStringPatterns(value string, patterns []string) bool {
	value = strings.TrimSpace(value)
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		p := strings.TrimSpace(pattern)
		if p == "*" || p == value {
			return true
		}
	}
	return false
}

func matchAnyPattern(values []string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, value := range values {
		if matchStringPatterns(value, patterns) {
			return true
		}
	}
	return false
}

type kernelVersion struct {
	Major int
	Minor int
	Patch int
}

var kernelVersionRegex = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?`)

func parseKernelVersion(raw string) (kernelVersion, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return kernelVersion{}, fmt.Errorf("kernel version is empty")
	}
	match := kernelVersionRegex.FindStringSubmatch(raw)
	if len(match) < 3 {
		return kernelVersion{}, fmt.Errorf("expected format <major>.<minor>[.<patch>]")
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	patch := 0
	if len(match) > 3 && strings.TrimSpace(match[3]) != "" {
		patch, _ = strconv.Atoi(match[3])
	}
	return kernelVersion{Major: major, Minor: minor, Patch: patch}, nil
}

func compareKernelVersion(a, b kernelVersion) int {
	switch {
	case a.Major < b.Major:
		return -1
	case a.Major > b.Major:
		return 1
	}
	switch {
	case a.Minor < b.Minor:
		return -1
	case a.Minor > b.Minor:
		return 1
	}
	switch {
	case a.Patch < b.Patch:
		return -1
	case a.Patch > b.Patch:
		return 1
	default:
		return 0
	}
}
