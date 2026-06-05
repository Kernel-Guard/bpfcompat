package agent

import (
	"testing"

	"github.com/erenari/bpfcompat/internal/registry"
	"github.com/erenari/bpfcompat/internal/runtime"
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
