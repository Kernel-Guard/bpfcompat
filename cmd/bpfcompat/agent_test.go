package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/erenari/bpfcompat/internal/agent"
	"github.com/erenari/bpfcompat/internal/registry"
	"github.com/erenari/bpfcompat/internal/runner"
)

func TestAgentApplyWithoutApprovalFetchesOnly(t *testing.T) {
	workDir := t.TempDir()
	artifactPath := filepath.Join(workDir, "aegis.bpf.o")
	artifactBytes := []byte{0x7f, 'E', 'L', 'F', 0x01, 0x02, 0x03}
	if err := os.WriteFile(artifactPath, artifactBytes, 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	sum := sha256.Sum256(artifactBytes)
	reportPath := filepath.Join(workDir, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"schema_version":"v0.1"}`), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := registry.PersistArtifactVersion(workDir, registry.ArtifactVersionRecord{
		RunID:             "run-1",
		ArtifactName:      "aegis",
		ArtifactVersion:   "v1",
		ArtifactPath:      artifactPath,
		ArtifactSHA256:    hex.EncodeToString(sum[:]),
		SummaryStatus:     "pass",
		RequiredPassed:    1,
		RequiredFailed:    0,
		SupportedProfiles: []string{"ubuntu-22.04-5.15"},
		JSONReportPath:    reportPath,
	}); err != nil {
		t.Fatalf("persist artifact version: %v", err)
	}
	outPath := filepath.Join(workDir, "agent-apply.json")
	outDir := filepath.Join(workDir, "selected")
	code := runAgentApply([]string{
		"--workdir", workDir,
		"--artifact-name", "aegis",
		"--probe-use-sudo=false",
		"--out-dir", outDir,
		"--out", outPath,
	})
	if code != runner.ExitSuccess {
		t.Fatalf("expected success, got exit code %d", code)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected apply JSON output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "aegis-v1.o")); err != nil {
		t.Fatalf("expected fetched artifact: %v", err)
	}

	status, err := summarizeAgentStatus(outPath)
	if err != nil {
		t.Fatalf("summarize agent status: %v", err)
	}
	if !status.Healthy {
		t.Fatalf("expected healthy fetch-only status: %+v", status)
	}
	if status.FetchStatus != "success" {
		t.Fatalf("unexpected fetch status: %s", status.FetchStatus)
	}
	if status.LoadStatus != "skipped" {
		t.Fatalf("unexpected load status: %s", status.LoadStatus)
	}
	if status.AuditStatus != "success" {
		t.Fatalf("unexpected audit status: %s", status.AuditStatus)
	}
}

func TestFetchAgentSelectedArtifactForwardsAuthHeaders(t *testing.T) {
	content := []byte("BPF-OBJECT")
	sum := sha256.Sum256(content)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer registry-token" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		if got := r.Header.Get(agentIdentityHeader); got != "identity-token" {
			t.Fatalf("unexpected identity header: %q", got)
		}
		_, _ = w.Write(content)
	}))
	defer server.Close()

	got, err := fetchAgentSelectedArtifact(
		registry.ArtifactVersionRecord{},
		agent.SelectedArtifact{
			Name:        "aegis",
			Version:     "v1",
			SHA256:      hex.EncodeToString(sum[:]),
			DownloadURL: "/download",
		},
		true,
		server.URL,
		"registry-token",
		"identity-token",
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("fetch selected artifact: %v", err)
	}
	if got.ActualSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected hash: %s", got.ActualSHA256)
	}
}

func TestAgentApplyWritesFailureStatus(t *testing.T) {
	workDir := t.TempDir()
	outPath := filepath.Join(workDir, "agent-apply.json")

	code := runAgentApply([]string{
		"--workdir", workDir,
		"--artifact-name", "missing-artifact",
		"--probe-use-sudo=false",
		"--out", outPath,
	})
	if code != runner.ExitToolError {
		t.Fatalf("expected tool error, got exit code %d", code)
	}

	status, err := summarizeAgentStatus(outPath)
	if err != nil {
		t.Fatalf("summarize failure status: %v", err)
	}
	if status.Healthy {
		t.Fatalf("expected unhealthy status: %+v", status)
	}
	if status.FetchStatus != "error" {
		t.Fatalf("unexpected fetch status: %s", status.FetchStatus)
	}
	if status.LastErrorPhase != "plan" {
		t.Fatalf("unexpected failure phase: %s", status.LastErrorPhase)
	}
	if !strings.Contains(status.LastError, "no artifact versions") {
		t.Fatalf("unexpected failure error: %s", status.LastError)
	}
}

func TestAgentApplyApprovedLoadDeniedByLocalPolicy(t *testing.T) {
	workDir := t.TempDir()
	artifactPath := filepath.Join(workDir, "aegis.bpf.o")
	artifactBytes := []byte{0x7f, 'E', 'L', 'F', 0x01, 0x02, 0x03}
	if err := os.WriteFile(artifactPath, artifactBytes, 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	sum := sha256.Sum256(artifactBytes)
	reportPath := filepath.Join(workDir, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"schema_version":"v0.1"}`), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := registry.PersistArtifactVersion(workDir, registry.ArtifactVersionRecord{
		RunID:             "run-1",
		ArtifactName:      "aegis",
		ArtifactVersion:   "v1",
		ArtifactPath:      artifactPath,
		ArtifactSHA256:    hex.EncodeToString(sum[:]),
		SummaryStatus:     "pass",
		RequiredPassed:    1,
		RequiredFailed:    0,
		SupportedProfiles: []string{"ubuntu-22.04-5.15"},
		JSONReportPath:    reportPath,
	}); err != nil {
		t.Fatalf("persist artifact version: %v", err)
	}
	policyPath := filepath.Join(workDir, "load-policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`schema_version: agent_load_policy.v0.1
default_action: deny
rules: []
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	outPath := filepath.Join(workDir, "agent-apply.json")
	code := runAgentApply([]string{
		"--workdir", workDir,
		"--artifact-name", "aegis",
		"--agent-id", "host-1",
		"--probe-use-sudo=false",
		"--out-dir", filepath.Join(workDir, "selected"),
		"--out", outPath,
		"--approve-load",
		"--load-policy", policyPath,
	})
	if code != runner.ExitToolError {
		t.Fatalf("expected policy denial tool error, got exit code %d", code)
	}

	status, err := summarizeAgentStatus(outPath)
	if err != nil {
		t.Fatalf("summarize denied status: %v", err)
	}
	if status.Healthy {
		t.Fatalf("expected unhealthy denied status: %+v", status)
	}
	if status.LoadPolicyStatus != "deny" {
		t.Fatalf("expected deny policy status, got %s", status.LoadPolicyStatus)
	}
	entries, err := agent.ListLoadLedgerEntries(workDir, "aegis", 1)
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one ledger entry, got %d", len(entries))
	}
	if entries[0].Status != "denied" {
		t.Fatalf("expected denied ledger status, got %+v", entries[0])
	}
}

func TestAgentRollbackRecordsDrill(t *testing.T) {
	workDir := t.TempDir()
	first := agent.LoadLedgerEntry{
		Operation:       "load",
		Status:          "pass",
		AgentID:         "host-1",
		ArtifactName:    "aegis",
		SelectedVersion: "v1",
		SelectedSHA256:  "sha-v1",
		ArtifactPath:    "/var/lib/bpfcompat-agent/selected/aegis-v1.o",
	}
	if _, err := agent.AppendLoadLedgerEntry(workDir, first); err != nil {
		t.Fatalf("append first load: %v", err)
	}
	second := agent.LoadLedgerEntry{
		Operation:                  "load",
		Status:                     "pass",
		AgentID:                    "host-1",
		ArtifactName:               "aegis",
		SelectedVersion:            "v2",
		SelectedSHA256:             "sha-v2",
		ArtifactPath:               "/var/lib/bpfcompat-agent/selected/aegis-v2.o",
		PreviousLoadedVersion:      "v1",
		PreviousLoadedSHA256:       "sha-v1",
		PreviousLoadedArtifactPath: "/var/lib/bpfcompat-agent/selected/aegis-v1.o",
	}
	if _, err := agent.AppendLoadLedgerEntry(workDir, second); err != nil {
		t.Fatalf("append second load: %v", err)
	}

	code := runAgentRollback([]string{
		"--workdir", workDir,
		"--artifact-name", "aegis",
		"--record=true",
		"--json",
	})
	if code != runner.ExitSuccess {
		t.Fatalf("expected rollback drill success, got %d", code)
	}
	entries, err := agent.ListLoadLedgerEntries(workDir, "aegis", 1)
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	if len(entries) != 1 || entries[0].Operation != "rollback_drill" || entries[0].Status != "ready" {
		t.Fatalf("unexpected rollback drill entry: %+v", entries)
	}
}

func TestAgentUnloadExecuteRemovesLabPin(t *testing.T) {
	workDir := t.TempDir()
	pinPath := filepath.Join(workDir, "pins", "aegis")
	if err := os.MkdirAll(filepath.Dir(pinPath), 0o755); err != nil {
		t.Fatalf("mkdir pin dir: %v", err)
	}
	if err := os.WriteFile(pinPath, []byte("pin"), 0o644); err != nil {
		t.Fatalf("write pin: %v", err)
	}

	code := runAgentUnload([]string{
		"--workdir", workDir,
		"--artifact-name", "aegis",
		"--pin-path", pinPath,
		"--allow-non-bpffs",
		"--execute",
		"--json",
	})
	if code != runner.ExitSuccess {
		t.Fatalf("expected unload success, got %d", code)
	}
	if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
		t.Fatalf("expected pin to be removed, stat err=%v", err)
	}
	entries, err := agent.ListLoadLedgerEntries(workDir, "aegis", 1)
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	if len(entries) != 1 || entries[0].Operation != "unload" || entries[0].Status != "pass" {
		t.Fatalf("unexpected unload ledger entry: %+v", entries)
	}
}

func TestAgentRevocationDrillRecordsDeniedIdentity(t *testing.T) {
	workDir := t.TempDir()
	policyPath := filepath.Join(workDir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`schema_version: agent_load_policy.v0.1
default_action: allow
revoked_agents: ["host-1"]
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	code := runAgentRevocationDrill([]string{
		"--workdir", workDir,
		"--agent-id", "host-1",
		"--artifact-name", "aegis",
		"--load-policy", policyPath,
		"--json",
	})
	if code != runner.ExitSuccess {
		t.Fatalf("expected revocation drill success, got %d", code)
	}
	entries, err := agent.ListLoadLedgerEntries(workDir, "aegis", 1)
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	if len(entries) != 1 || entries[0].Operation != "revocation_drill" || entries[0].Status != "pass" {
		t.Fatalf("unexpected revocation drill entry: %+v", entries)
	}
}
