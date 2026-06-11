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

	"github.com/kernel-guard/bpfcompat/internal/agent"
	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/internal/runtime"
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

func TestBuildAgentLoadLedgerEntryIncludesApprovalAndManifestEvidence(t *testing.T) {
	workDir := t.TempDir()
	manifestPath := writeAgentTestManifest(t, workDir)
	sum := strings.Repeat("d", 64)
	payload := agentApplyResultFile{
		Decision: agent.DecisionResult{
			DecisionID: "20260606T120000Z-abcdef",
			Tenant:     "acme",
			Project:    "aegis-bpf",
			AgentID:    "host-1",
			SelectedArtifact: agent.SelectedArtifact{
				Name:    "aegis",
				Version: "v1",
				SHA256:  sum,
			},
			LoadApproved: true,
		},
		Fetch: runtime.FetchResult{
			ArtifactName:    "aegis",
			ArtifactVersion: "v1",
			OutputPath:      filepath.Join(workDir, "selected", "aegis-v1.o"),
			ExpectedSHA256:  sum,
			ActualSHA256:    sum,
		},
		ApprovalPins: &agentApprovalPins{
			Required:           true,
			ExpectedDecisionID: "20260606T120000Z-abcdef",
			ExpectedSHA256:     sum,
			Verified:           true,
		},
		ManifestIntent: &agentManifestIntent{
			Required:     true,
			Path:         manifestPath,
			ProgramCount: 1,
			Valid:        true,
		},
	}

	entry, err := buildAgentLoadLedgerEntry(workDir, payload, "load", "pass", "")
	if err != nil {
		t.Fatalf("build ledger entry: %v", err)
	}
	if !entry.ApprovalPinsRequired || !entry.ApprovalPinsVerified {
		t.Fatalf("expected verified approval pin evidence: %+v", entry)
	}
	if entry.ApprovalExpectedDecisionID != payload.ApprovalPins.ExpectedDecisionID {
		t.Fatalf("unexpected decision pin: %+v", entry)
	}
	if entry.ApprovalExpectedSHA256 != sum {
		t.Fatalf("unexpected sha pin: %+v", entry)
	}
	if !entry.ManifestIntentRequired || !entry.ManifestIntentVerified {
		t.Fatalf("expected verified manifest evidence: %+v", entry)
	}
	if entry.ManifestPath != manifestPath || entry.ManifestProgramCount != 1 {
		t.Fatalf("unexpected manifest evidence: %+v", entry)
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

func TestAgentPreflightFetchOnlyPasses(t *testing.T) {
	workDir := t.TempDir()
	outDir := filepath.Join(workDir, "selected")

	code := runAgentPreflight([]string{
		"--workdir", workDir,
		"--out-dir", outDir,
		"--agent-id", "host-1",
		"--check-host-probe=false",
		"--json",
	})
	if code != runner.ExitSuccess {
		t.Fatalf("expected preflight success, got %d", code)
	}

	result := buildAgentPreflight(agentPreflightOptions{
		WorkDir:        workDir,
		OutDir:         outDir,
		AgentID:        "host-1",
		CheckHostProbe: false,
	})
	if result.Status != "pass" {
		t.Fatalf("expected pass result: %+v", result)
	}
	if checkStatus(result, "load_policy") != "skip" {
		t.Fatalf("expected fetch-only load policy skip: %+v", result.Checks)
	}
	if checkStatus(result, "validator_binary") != "skip" {
		t.Fatalf("expected fetch-only validator skip: %+v", result.Checks)
	}
}

func TestAgentPreflightIncludeLoadValidatesPolicyAndValidator(t *testing.T) {
	workDir := t.TempDir()
	policyPath := filepath.Join(workDir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`schema_version: agent_load_policy.v0.1
default_action: deny
rules: []
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	validatorPath := filepath.Join(workDir, "bpfcompat-validator")
	if err := os.WriteFile(validatorPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write validator: %v", err)
	}
	manifestPath := writeAgentTestManifest(t, workDir)

	result := buildAgentPreflight(agentPreflightOptions{
		WorkDir:            workDir,
		OutDir:             filepath.Join(workDir, "selected"),
		AgentID:            "host-1",
		LoadPolicyPath:     policyPath,
		RequireLoadPolicy:  true,
		ExpectedDecisionID: "20260606T120000Z-abcdef",
		ExpectedSHA256:     strings.Repeat("a", 64),
		RequirePins:        true,
		ManifestPath:       manifestPath,
		RequireManifest:    true,
		ValidatorPath:      validatorPath,
		IncludeLoad:        true,
		CheckHostProbe:     false,
	})
	if result.Status != "pass" {
		t.Fatalf("expected load preflight pass: %+v", result)
	}
	if checkStatus(result, "load_policy") != "pass" {
		t.Fatalf("expected load policy pass: %+v", result.Checks)
	}
	if checkStatus(result, "validator_binary") != "pass" {
		t.Fatalf("expected validator pass: %+v", result.Checks)
	}
	if checkStatus(result, "approval_pins") != "pass" {
		t.Fatalf("expected approval pins pass: %+v", result.Checks)
	}
	if checkStatus(result, "manifest_intent") != "pass" {
		t.Fatalf("expected manifest intent pass: %+v", result.Checks)
	}
}

func TestAgentPreflightIncludeLoadFailsWithoutPolicy(t *testing.T) {
	workDir := t.TempDir()
	result := buildAgentPreflight(agentPreflightOptions{
		WorkDir:           workDir,
		OutDir:            filepath.Join(workDir, "selected"),
		AgentID:           "host-1",
		RequireLoadPolicy: true,
		IncludeLoad:       true,
		CheckHostProbe:    false,
	})
	if result.Status != "fail" {
		t.Fatalf("expected load preflight failure: %+v", result)
	}
	if checkStatus(result, "load_policy") != "fail" {
		t.Fatalf("expected load policy failure: %+v", result.Checks)
	}
}

func TestAgentPreflightIncludeLoadRequiresApprovalPins(t *testing.T) {
	workDir := t.TempDir()
	result := buildAgentPreflight(agentPreflightOptions{
		WorkDir:        workDir,
		OutDir:         filepath.Join(workDir, "selected"),
		AgentID:        "host-1",
		IncludeLoad:    true,
		RequirePins:    true,
		CheckHostProbe: false,
	})
	if result.Status != "fail" {
		t.Fatalf("expected load preflight failure: %+v", result)
	}
	if checkStatus(result, "approval_pins") != "fail" {
		t.Fatalf("expected approval pins failure: %+v", result.Checks)
	}
}

func TestAgentPreflightIncludeLoadRequiresManifest(t *testing.T) {
	workDir := t.TempDir()
	result := buildAgentPreflight(agentPreflightOptions{
		WorkDir:            workDir,
		OutDir:             filepath.Join(workDir, "selected"),
		AgentID:            "host-1",
		ExpectedDecisionID: "20260606T120000Z-abcdef",
		ExpectedSHA256:     strings.Repeat("a", 64),
		RequirePins:        true,
		IncludeLoad:        true,
		RequireManifest:    true,
		CheckHostProbe:     false,
	})
	if result.Status != "fail" {
		t.Fatalf("expected load preflight failure: %+v", result)
	}
	if checkStatus(result, "manifest_intent") != "fail" {
		t.Fatalf("expected manifest intent failure: %+v", result.Checks)
	}
}

func TestValidateAgentApprovalPins(t *testing.T) {
	sum := strings.Repeat("b", 64)
	decision := agent.DecisionResult{
		DecisionID: "20260606T120000Z-abcdef",
		SelectedArtifact: agent.SelectedArtifact{
			SHA256: sum,
		},
	}
	fetch := runtime.FetchResult{ActualSHA256: sum}
	if err := validateAgentApprovalPins(decision, fetch, decision.DecisionID, sum, true); err != nil {
		t.Fatalf("expected approval pins to validate: %v", err)
	}
	if err := validateAgentApprovalPins(decision, fetch, "wrong", sum, true); err == nil || !strings.Contains(err.Error(), "decision id mismatch") {
		t.Fatalf("expected decision mismatch, got %v", err)
	}
	if err := validateAgentApprovalPins(decision, fetch, decision.DecisionID, strings.Repeat("c", 64), true); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha mismatch, got %v", err)
	}
	if err := validateAgentApprovalPins(decision, fetch, "", "", true); err == nil || !strings.Contains(err.Error(), "--expected-decision-id") {
		t.Fatalf("expected required pins error, got %v", err)
	}
}

func TestValidateAgentManifestIntent(t *testing.T) {
	workDir := t.TempDir()
	manifestPath := writeAgentTestManifest(t, workDir)
	if err := validateAgentManifestIntent(manifestPath, true); err != nil {
		t.Fatalf("expected manifest intent to validate: %v", err)
	}
	if err := validateAgentManifestIntent("", true); err == nil || !strings.Contains(err.Error(), "--manifest is required") {
		t.Fatalf("expected required manifest error, got %v", err)
	}
	emptyPath := filepath.Join(workDir, "empty-manifest.yaml")
	if err := os.WriteFile(emptyPath, []byte("name: empty\n"), 0o644); err != nil {
		t.Fatalf("write empty manifest: %v", err)
	}
	if err := validateAgentManifestIntent(emptyPath, true); err == nil || !strings.Contains(err.Error(), "at least one program") {
		t.Fatalf("expected empty manifest error, got %v", err)
	}
}

func checkStatus(result agentPreflightResult, name string) string {
	for _, check := range result.Checks {
		if check.Name == name {
			return check.Status
		}
	}
	return ""
}

func writeAgentTestManifest(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "manifest.yaml")
	raw := []byte(`name: aegis
programs:
  - name: prog
    section: tracepoint/syscalls/sys_enter_execve
    type: tracepoint
    attach:
      kind: tracepoint
      category: syscalls
      name: sys_enter_execve
      required: true
`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}
