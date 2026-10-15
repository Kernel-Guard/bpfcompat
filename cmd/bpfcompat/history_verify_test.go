package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/agent"
	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/internal/runtime"
)

// truncatedHistoryWorkdir persists a 3-record signed history, returns the
// record hashes, and then drops the newest record (a silent rollback).
func truncatedHistoryWorkdir(t *testing.T) (string, []string) {
	t.Helper()
	t.Setenv("BPFCOMPAT_SIGNING_MODE", "")
	t.Setenv("BPFCOMPAT_TRUSTED_SIGNING_PUBLIC_KEYS", "")
	t.Setenv("BPFCOMPAT_TRUSTED_SIGNING_KEYS_PATH", "")
	workDir := t.TempDir()
	for _, v := range []string{"v1", "v2", "v3"} {
		if err := registry.PersistArtifactVersion(workDir, registry.ArtifactVersionRecord{
			RunID:           "run-" + v,
			RunStartedAt:    "2026-10-15T00:00:00Z",
			CreatedAt:       "2026-10-15T00:00:00Z",
			ArtifactName:    "app",
			ArtifactVersion: v,
			ArtifactSHA256:  "sha-" + v,
			ArtifactPath:    "/srv/app-" + v + ".o",
			MatrixPath:      "/m.yaml",
			SummaryStatus:   "pass",
			JSONReportPath:  "/r.json",
		}); err != nil {
			t.Fatalf("persist %s: %v", v, err)
		}
	}
	rows, err := registry.VerifyArtifactVersionHistory(workDir)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	hashes := make([]string, 0, len(rows))
	for _, row := range rows {
		hashes = append(hashes, row.RecordSHA256)
	}
	indexPath := filepath.Join(workDir, "registry", "artifact_versions.jsonl")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if err := os.WriteFile(indexPath, append(bytes.Join(lines[:2], []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return workDir, hashes
}

func TestHistoryVerifyExpectHeadAndMinRecords(t *testing.T) {
	workDir, hashes := truncatedHistoryWorkdir(t)

	cases := []struct {
		name string
		args []string
		want int
	}{
		// Known limitation (SIGN-3): plain verify accepts the truncated chain.
		{"plain verify", nil, runner.ExitSuccess},
		{"expect old head (record 3)", []string{"--expect-head", hashes[2]}, runner.ExitToolError},
		{"min records 3", []string{"--min-records", "3"}, runner.ExitToolError},
		{"correct head", []string{"--expect-head", hashes[1], "--min-records", "2"}, runner.ExitSuccess},
		{"invalid sha", []string{"--expect-head", "xyz"}, runner.ExitToolError},
		{"negative count", []string{"--min-records", "-1"}, runner.ExitToolError},
		{"json expect old head", []string{"--json", "--expect-head", hashes[2]}, runner.ExitToolError},
	}
	for _, tc := range cases {
		capture, restore := captureStdout(t)
		code := runHistoryVerify(append([]string{"--workdir", workDir}, tc.args...))
		_ = capture.read()
		restore()
		if code != tc.want {
			t.Fatalf("%s: exit=%d want %d", tc.name, code, tc.want)
		}
	}
}

func TestHistoryVerifyReportsHead(t *testing.T) {
	workDir, hashes := truncatedHistoryWorkdir(t)

	capture, restore := captureStdout(t)
	code := runHistoryVerify([]string{"--workdir", workDir})
	out := string(capture.read())
	restore()
	if code != runner.ExitSuccess {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out, "head_sha256="+hashes[1]) || !strings.Contains(out, "records=2") {
		t.Fatalf("human output does not report head/records: %q", out)
	}

	// --json keeps its existing array shape (scripts pipe it into `jq length`).
	capture, restore = captureStdout(t)
	code = runHistoryVerify([]string{"--workdir", workDir, "--json"})
	raw := capture.read()
	restore()
	if code != runner.ExitSuccess {
		t.Fatalf("json exit=%d", code)
	}
	var rows []registry.ArtifactVersionVerification
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("--json is no longer an array: %v (%s)", err, raw)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d", len(rows))
	}
}

func TestAgentLocalLoadPolicyUsesHistoryHead(t *testing.T) {
	head := strings.Repeat("d4", 32)
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	body := "schema_version: agent_load_policy.v0.1\ndefault_action: deny\nrules:\n" +
		"  - name: pinned\n    action: allow\n    require_verified_history: true\n" +
		"    expect_head_sha256: " + head + "\n    min_records: 3\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		head    string
		records int
		allowed bool
	}{
		{head, 3, true},
		{strings.Repeat("e5", 32), 2, false},
	} {
		decision := agent.DecisionResult{
			AgentID:      "host-1",
			ArtifactName: "app",
			HistoryVerification: &runtime.HistoryVerificationResult{
				Verified:   true,
				Records:    tc.records,
				HeadSHA256: tc.head,
			},
		}
		got, err := evaluateAgentLocalLoadPolicy(policyPath, true, decision, registry.ArtifactVersionRecord{}, runtime.HostCapabilities{}, "")
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got.Allowed != tc.allowed {
			t.Fatalf("case %d: allowed=%v want %v (%+v)", i, got.Allowed, tc.allowed, got)
		}
	}
}
