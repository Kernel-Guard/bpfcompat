package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/erenari/bpfcompat/internal/registry"
	"github.com/erenari/bpfcompat/internal/runtime"
)

func TestBuildDecisionSelectsVerifiedStrictCandidate(t *testing.T) {
	workDir := t.TempDir()
	reportPath := filepath.Join(workDir, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"schema_version":"v0.1"}`), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := registry.PersistArtifactVersion(workDir, registry.ArtifactVersionRecord{
		RunID:             "run-old",
		ArtifactName:      "aegis",
		ArtifactVersion:   "old",
		ArtifactSHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SummaryStatus:     "fail",
		RequiredFailed:    1,
		SupportedProfiles: []string{"ubuntu-20.04-5.4"},
		FailedProfiles:    []string{"ubuntu-22.04-5.15"},
		JSONReportPath:    reportPath,
	}); err != nil {
		t.Fatalf("persist old record: %v", err)
	}
	if err := registry.PersistArtifactVersion(workDir, registry.ArtifactVersionRecord{
		RunID:             "run-new",
		ArtifactName:      "aegis",
		ArtifactVersion:   "new",
		ArtifactSHA256:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SummaryStatus:     "pass",
		RequiredPassed:    2,
		RequiredFailed:    0,
		SupportedProfiles: []string{"ubuntu-22.04-5.15"},
		JSONReportPath:    reportPath,
	}); err != nil {
		t.Fatalf("persist new record: %v", err)
	}
	records, err := registry.ListArtifactVersions(workDir, "aegis", 0)
	if err != nil {
		t.Fatalf("list records: %v", err)
	}

	host := runtime.HostCapabilities{SchemaVersion: "runtime_probe.v0.1"}
	host.OS.ID = "ubuntu"
	host.OS.VersionID = "22.04"
	host.Kernel.Release = "5.15.0-100-generic"
	host.BTF.KernelAvailable = true
	maxFailed := 0
	decision, selected, err := BuildDecision(workDir, records, DecisionRequest{
		ArtifactName: "aegis",
		HostProbe:    host,
		Policy: runtime.SelectionPolicy{
			RequireSummaryPass: true,
			MaxRequiredFailed:  &maxFailed,
		},
	})
	if err != nil {
		t.Fatalf("build decision: %v", err)
	}
	if selected.ArtifactVersion != "new" {
		t.Fatalf("expected new selected record, got %s", selected.ArtifactVersion)
	}
	if decision.SelectedArtifact.Version != "new" {
		t.Fatalf("expected new selected artifact, got %s", decision.SelectedArtifact.Version)
	}
	if decision.HistoryVerification == nil || !decision.HistoryVerification.Verified {
		t.Fatalf("expected verified history, got %+v", decision.HistoryVerification)
	}
	if !decision.ApprovalRequired {
		t.Fatalf("agent decision should require approval before load")
	}
	if decision.LoadApproved {
		t.Fatalf("agent decision must not approve load by default")
	}
}

func TestBuildDecisionRequiresHostProbe(t *testing.T) {
	_, _, err := BuildDecision(t.TempDir(), nil, DecisionRequest{ArtifactName: "aegis"})
	if err == nil {
		t.Fatalf("expected missing host_probe error")
	}
}
