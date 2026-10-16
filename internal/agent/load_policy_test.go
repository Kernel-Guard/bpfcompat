package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/runtime"
)

func TestEvaluateLoadPolicyAllowsMatchingAgentArtifactAndKernel(t *testing.T) {
	verified := true
	policy := LoadPolicy{
		DefaultAction: "deny",
		AllowedAgents: []string{
			"host-*",
		},
		Rules: []LoadPolicyRule{
			{
				Name:                   "allow-aegis-new-kernel",
				Action:                 "allow",
				Agents:                 []string{"host-1"},
				Tenants:                []string{"acme"},
				Projects:               []string{"aegis-bpf"},
				Artifacts:              []string{"aegis"},
				Profiles:               []string{"ubuntu-24.04-6.8"},
				KernelMin:              "6.8.0",
				RequireVerifiedHistory: &verified,
			},
		},
	}
	if err := policy.NormalizeAndValidate(); err != nil {
		t.Fatalf("normalize policy: %v", err)
	}
	var host runtime.HostCapabilities
	host.Kernel.Release = "6.8.0-60-generic"

	decision := EvaluateLoadPolicy(policy, LoadPolicyContext{
		AgentID:         "host-1",
		Tenant:          "acme",
		Project:         "aegis-bpf",
		ArtifactName:    "aegis",
		TargetProfileID: "ubuntu-24.04-6.8",
		SelectedRecord: registry.ArtifactVersionRecord{
			SupportedProfiles: []string{"ubuntu-24.04-6.8"},
		},
		HostProbe:       &host,
		HistoryVerified: true,
	})
	if !decision.Allowed {
		t.Fatalf("expected allow decision, got %+v", decision)
	}
	if decision.RuleName != "allow-aegis-new-kernel" {
		t.Fatalf("unexpected rule: %s", decision.RuleName)
	}
}

func TestEvaluateLoadPolicyDeniesRevokedAgent(t *testing.T) {
	policy := LoadPolicy{
		DefaultAction: "allow",
		RevokedAgents: []string{
			"host-1",
		},
	}
	decision := EvaluateLoadPolicy(policy, LoadPolicyContext{
		AgentID:      "host-1",
		ArtifactName: "aegis",
	})
	if decision.Allowed {
		t.Fatalf("expected revoked agent to be denied")
	}
	if decision.RuleName != "revoked_agents" {
		t.Fatalf("unexpected rule: %s", decision.RuleName)
	}
}

func TestEvaluateLoadPolicyExpectHeadAndMinRecords(t *testing.T) {
	verified := true
	head := strings.Repeat("a1", 32)
	older := strings.Repeat("b2", 32)
	policy := LoadPolicy{
		DefaultAction: "deny",
		Rules: []LoadPolicyRule{{
			Name:                   "allow-pinned-head",
			Action:                 "allow",
			Artifacts:              []string{"aegis"},
			RequireVerifiedHistory: &verified,
			ExpectHeadSHA256:       strings.ToUpper(head),
			MinRecords:             3,
		}},
	}
	if err := policy.NormalizeAndValidate(); err != nil {
		t.Fatalf("normalize policy: %v", err)
	}
	if policy.Rules[0].ExpectHeadSHA256 != head {
		t.Fatalf("expect_head_sha256 not normalized: %q", policy.Rules[0].ExpectHeadSHA256)
	}

	base := LoadPolicyContext{AgentID: "host-1", ArtifactName: "aegis", HistoryVerified: true}
	cases := []struct {
		name    string
		head    string
		records int
		allowed bool
	}{
		{"pinned head and count", head, 3, true},
		{"different head with more records", older, 4, false},
		{"truncated history (rolled back head)", older, 2, false},
		{"head matches but too few records", head, 2, false},
		{"no history verification", "", 0, false},
	}
	for _, tc := range cases {
		ctx := base
		ctx.HistoryHeadSHA256 = tc.head
		ctx.HistoryRecords = tc.records
		decision := EvaluateLoadPolicy(policy, ctx)
		if decision.Allowed != tc.allowed {
			t.Fatalf("%s: allowed=%v want %v (%+v)", tc.name, decision.Allowed, tc.allowed, decision)
		}
	}

	// Absent fields keep the existing behaviour.
	unpinned := LoadPolicy{DefaultAction: "deny", Rules: []LoadPolicyRule{{
		Name: "allow", Action: "allow", Artifacts: []string{"aegis"}, RequireVerifiedHistory: &verified,
	}}}
	if !EvaluateLoadPolicy(unpinned, base).Allowed {
		t.Fatalf("rule without head pin should still allow a verified history")
	}
}

func TestLoadPolicyRejectsInvalidHeadPin(t *testing.T) {
	for _, rule := range []LoadPolicyRule{
		{Name: "bad-sha", Action: "allow", ExpectHeadSHA256: "deadbeef"},
		{Name: "neg-count", Action: "allow", MinRecords: -1},
	} {
		policy := LoadPolicy{DefaultAction: "deny", Rules: []LoadPolicyRule{rule}}
		if err := policy.NormalizeAndValidate(); err == nil {
			t.Fatalf("expected validation error for rule %q", rule.Name)
		}
	}
}

func TestLoadLoadPolicyParsesHeadPinFields(t *testing.T) {
	head := strings.Repeat("c3", 32)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := "schema_version: agent_load_policy.v0.1\ndefault_action: deny\nrules:\n" +
		"  - name: pinned\n    action: allow\n    require_verified_history: true\n" +
		"    expect_head_sha256: " + head + "\n    min_records: 7\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadLoadPolicy(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if policy.Rules[0].ExpectHeadSHA256 != head || policy.Rules[0].MinRecords != 7 {
		t.Fatalf("unexpected parsed rule: %+v", policy.Rules[0])
	}
}
