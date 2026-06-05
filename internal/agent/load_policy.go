package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
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

const LoadPolicySchemaVersion = "agent_load_policy.v0.1"

type LoadPolicy struct {
	SchemaVersion string           `json:"schema_version" yaml:"schema_version"`
	DefaultAction string           `json:"default_action" yaml:"default_action"`
	AllowedAgents []string         `json:"allowed_agents,omitempty" yaml:"allowed_agents,omitempty"`
	RevokedAgents []string         `json:"revoked_agents,omitempty" yaml:"revoked_agents,omitempty"`
	Rules         []LoadPolicyRule `json:"rules" yaml:"rules"`
}

type LoadPolicyRule struct {
	Name                   string   `json:"name" yaml:"name"`
	Action                 string   `json:"action" yaml:"action"`
	Agents                 []string `json:"agents,omitempty" yaml:"agents,omitempty"`
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

type LoadPolicyContext struct {
	AgentID         string
	Tenant          string
	Project         string
	ArtifactName    string
	TargetProfileID string
	SelectedRecord  registry.ArtifactVersionRecord
	HostProbe       *runtime.HostCapabilities
	HistoryVerified bool
	Manifest        *manifest.Manifest
}

type LoadPolicyDecision struct {
	SchemaVersion string `json:"schema_version"`
	Allowed       bool   `json:"allowed"`
	RuleName      string `json:"rule_name"`
	Action        string `json:"action"`
	Reason        string `json:"reason"`
}

func LoadLoadPolicy(path string) (LoadPolicy, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return LoadPolicy{}, fmt.Errorf("load policy path is required")
	}
	cleanPath = filepath.Clean(cleanPath)
	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return LoadPolicy{}, fmt.Errorf("read agent load policy: %w", err)
	}

	var policy LoadPolicy
	switch strings.ToLower(filepath.Ext(cleanPath)) {
	case ".yaml", ".yml":
		decoder := yaml.NewDecoder(bytes.NewReader(raw))
		decoder.KnownFields(true)
		if err := decoder.Decode(&policy); err != nil {
			return LoadPolicy{}, fmt.Errorf("parse agent load policy YAML: %w", err)
		}
	default:
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&policy); err != nil {
			return LoadPolicy{}, fmt.Errorf("parse agent load policy JSON: %w", err)
		}
	}
	if err := policy.NormalizeAndValidate(); err != nil {
		return LoadPolicy{}, err
	}
	return policy, nil
}

func (p *LoadPolicy) NormalizeAndValidate() error {
	if strings.TrimSpace(p.SchemaVersion) != "" && strings.TrimSpace(p.SchemaVersion) != LoadPolicySchemaVersion {
		return fmt.Errorf("agent load policy schema_version must be %s", LoadPolicySchemaVersion)
	}
	p.DefaultAction = normalizeLoadAction(p.DefaultAction)
	if p.DefaultAction == "" {
		p.DefaultAction = "deny"
	}
	if !isLoadAction(p.DefaultAction) {
		return fmt.Errorf("agent load policy default_action must be allow or deny")
	}
	p.AllowedAgents = normalizePatternList(p.AllowedAgents, false)
	p.RevokedAgents = normalizePatternList(p.RevokedAgents, false)

	for i := range p.Rules {
		rule := &p.Rules[i]
		rule.Name = strings.TrimSpace(rule.Name)
		if rule.Name == "" {
			rule.Name = fmt.Sprintf("rule-%d", i+1)
		}
		rule.Action = normalizeLoadAction(rule.Action)
		if !isLoadAction(rule.Action) {
			return fmt.Errorf("agent load policy rule %q action must be allow or deny", rule.Name)
		}
		rule.Agents = normalizePatternList(rule.Agents, false)
		rule.Tenants = normalizePatternList(rule.Tenants, false)
		rule.Projects = normalizePatternList(rule.Projects, false)
		rule.Artifacts = normalizePatternList(rule.Artifacts, false)
		rule.Profiles = normalizePatternList(rule.Profiles, false)
		rule.ProgramTypes = normalizePatternList(rule.ProgramTypes, true)
		rule.AttachKinds = normalizePatternList(rule.AttachKinds, true)
		rule.KernelMin = strings.TrimSpace(rule.KernelMin)
		rule.KernelMax = strings.TrimSpace(rule.KernelMax)
		if rule.KernelMin != "" {
			if _, err := parseAgentKernelVersion(rule.KernelMin); err != nil {
				return fmt.Errorf("agent load policy rule %q invalid kernel_min %q: %w", rule.Name, rule.KernelMin, err)
			}
		}
		if rule.KernelMax != "" {
			if _, err := parseAgentKernelVersion(rule.KernelMax); err != nil {
				return fmt.Errorf("agent load policy rule %q invalid kernel_max %q: %w", rule.Name, rule.KernelMax, err)
			}
		}
	}
	return nil
}

func EvaluateLoadPolicy(policy LoadPolicy, ctx LoadPolicyContext) LoadPolicyDecision {
	_ = policy.NormalizeAndValidate()
	agentID := strings.ToLower(strings.TrimSpace(ctx.AgentID))
	if len(policy.RevokedAgents) > 0 && matchStringPatterns(agentID, policy.RevokedAgents) {
		return LoadPolicyDecision{
			SchemaVersion: LoadPolicySchemaVersion,
			Allowed:       false,
			RuleName:      "revoked_agents",
			Action:        "deny",
			Reason:        "agent identity is revoked by local load policy",
		}
	}
	if len(policy.AllowedAgents) > 0 && !matchStringPatterns(agentID, policy.AllowedAgents) {
		return LoadPolicyDecision{
			SchemaVersion: LoadPolicySchemaVersion,
			Allowed:       false,
			RuleName:      "allowed_agents",
			Action:        "deny",
			Reason:        "agent identity is not in local load policy allowed_agents",
		}
	}

	for i := range policy.Rules {
		rule := &policy.Rules[i]
		if !loadRuleMatches(*rule, ctx) {
			continue
		}
		return LoadPolicyDecision{
			SchemaVersion: LoadPolicySchemaVersion,
			Allowed:       rule.Action == "allow",
			RuleName:      rule.Name,
			Action:        rule.Action,
			Reason:        fmt.Sprintf("matched local load policy rule %q", rule.Name),
		}
	}
	action := policy.DefaultAction
	if action == "" {
		action = "deny"
	}
	return LoadPolicyDecision{
		SchemaVersion: LoadPolicySchemaVersion,
		Allowed:       action == "allow",
		RuleName:      "default",
		Action:        action,
		Reason:        "no local load policy rule matched; default_action applied",
	}
}

func loadRuleMatches(rule LoadPolicyRule, ctx LoadPolicyContext) bool {
	if !matchStringPatterns(strings.ToLower(strings.TrimSpace(ctx.AgentID)), rule.Agents) {
		return false
	}
	if !matchStringPatterns(strings.ToLower(strings.TrimSpace(ctx.Tenant)), rule.Tenants) {
		return false
	}
	if !matchStringPatterns(strings.ToLower(strings.TrimSpace(ctx.Project)), rule.Projects) {
		return false
	}
	if !matchStringPatterns(strings.ToLower(strings.TrimSpace(ctx.ArtifactName)), rule.Artifacts) {
		return false
	}
	if rule.RequireVerifiedHistory != nil && *rule.RequireVerifiedHistory != ctx.HistoryVerified {
		return false
	}
	if len(rule.Profiles) > 0 && !matchAnyPattern(loadPolicyProfileCandidates(ctx), rule.Profiles) {
		return false
	}
	if strings.TrimSpace(rule.KernelMin) != "" || strings.TrimSpace(rule.KernelMax) != "" {
		if ctx.HostProbe == nil {
			return false
		}
		hostVersion, err := parseAgentKernelVersion(ctx.HostProbe.Kernel.Release)
		if err != nil {
			return false
		}
		if strings.TrimSpace(rule.KernelMin) != "" {
			minVersion, _ := parseAgentKernelVersion(rule.KernelMin)
			if compareAgentKernelVersion(hostVersion, minVersion) < 0 {
				return false
			}
		}
		if strings.TrimSpace(rule.KernelMax) != "" {
			maxVersion, _ := parseAgentKernelVersion(rule.KernelMax)
			if compareAgentKernelVersion(hostVersion, maxVersion) > 0 {
				return false
			}
		}
	}
	if len(rule.ProgramTypes) > 0 {
		if ctx.Manifest == nil {
			return false
		}
		var values []string
		for _, program := range ctx.Manifest.Programs {
			values = append(values, strings.ToUpper(strings.TrimSpace(program.Type)))
		}
		if !matchAnyPattern(values, rule.ProgramTypes) {
			return false
		}
	}
	if len(rule.AttachKinds) > 0 {
		if ctx.Manifest == nil {
			return false
		}
		var values []string
		for _, program := range ctx.Manifest.Programs {
			values = append(values, strings.ToUpper(strings.TrimSpace(program.Attach.Kind)))
		}
		if !matchAnyPattern(values, rule.AttachKinds) {
			return false
		}
	}
	return true
}

func loadPolicyProfileCandidates(ctx LoadPolicyContext) []string {
	seen := make(map[string]struct{})
	var out []string
	appendUnique := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
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

func normalizeLoadAction(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isLoadAction(value string) bool {
	return value == "allow" || value == "deny"
}

func normalizePatternList(values []string, upper bool) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		clean := strings.TrimSpace(value)
		if clean == "" {
			continue
		}
		if upper {
			clean = strings.ToUpper(clean)
		} else {
			clean = strings.ToLower(clean)
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

func matchAnyPattern(values, patterns []string) bool {
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

func matchStringPatterns(value string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	value = strings.TrimSpace(value)
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if pattern == "*" || pattern == value {
			return true
		}
		if ok, err := path.Match(pattern, value); err == nil && ok {
			return true
		}
	}
	return false
}

type agentKernelVersion [3]int

var agentKernelVersionRe = regexp.MustCompile(`\d+`)

func parseAgentKernelVersion(raw string) (agentKernelVersion, error) {
	parts := agentKernelVersionRe.FindAllString(raw, 3)
	if len(parts) < 2 {
		return agentKernelVersion{}, fmt.Errorf("expected at least major.minor in kernel release")
	}
	var out agentKernelVersion
	for i := range out {
		if i >= len(parts) {
			break
		}
		value, err := strconv.Atoi(parts[i])
		if err != nil {
			return agentKernelVersion{}, err
		}
		out[i] = value
	}
	return out, nil
}

func compareAgentKernelVersion(a, b agentKernelVersion) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
