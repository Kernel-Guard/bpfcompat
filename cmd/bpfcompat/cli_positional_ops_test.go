package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/cloudregistry"
	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/runner"
)

// seedDemoHistory persists two signed versions of artifact "demo": v1 is
// clean, v2 (newer, so preferred by default) carries the
// UNSUPPORTED_ATTACH_TYPE classification. It returns v1's SHA-256.
func seedDemoHistory(t *testing.T, workDir string) string {
	t.Helper()
	var v1SHA string
	for _, v := range []struct {
		ver, created string
		codes        []string
	}{
		{"v1", "2026-01-01T00:00:00Z", nil},
		{"v2", "2026-02-01T00:00:00Z", []string{"UNSUPPORTED_ATTACH_TYPE"}},
	} {
		src := filepath.Join(workDir, "src")
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatal(err)
		}
		body := []byte("fake-object-" + v.ver)
		objPath := filepath.Join(src, "demo-"+v.ver+".bpf.o")
		if err := os.WriteFile(objPath, body, 0o644); err != nil {
			t.Fatal(err)
		}
		reportPath := filepath.Join(src, v.ver+".json")
		if err := os.WriteFile(reportPath, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		if v.ver == "v1" {
			v1SHA = hex.EncodeToString(sum[:])
		}
		if err := registry.PersistArtifactVersion(workDir, registry.ArtifactVersionRecord{
			RunID: "run-" + v.ver, RunStartedAt: v.created, CreatedAt: v.created,
			ArtifactName: "demo", ArtifactVersion: v.ver, ArtifactPath: objPath,
			ArtifactSHA256: hex.EncodeToString(sum[:]), MatrixPath: "m.yaml",
			SummaryStatus: "pass", RequiredPassed: 1, TotalProfiles: 1,
			SupportedProfiles: []string{"ubuntu-22.04"}, ClassificationCode: v.codes,
			JSONReportPath: reportPath,
		}); err != nil {
			t.Fatalf("persist %s: %v", v.ver, err)
		}
	}
	return v1SHA
}

// writeRecordingValidator writes a fake validator that records every
// invocation in invoked.log next to itself.
func writeRecordingValidator(t *testing.T, dir string) (validator, log string) {
	t.Helper()
	validator = filepath.Join(dir, "fake-validator")
	log = filepath.Join(dir, "invoked.log")
	script := "#!/bin/sh\necho \"$@\" >> '" + log + "'\necho '{}'\nexit 0\n"
	if err := os.WriteFile(validator, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return validator, log
}

// treeSnapshot maps every path under root to its mode and content hash, so
// any created, removed or modified file shows up as a difference.
func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := info.Mode().String()
		if info.Mode().IsRegular() {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(body)
			entry += " " + hex.EncodeToString(sum[:])
		}
		snap[path] = entry
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return snap
}

func diffSnapshots(before, after map[string]string) []string {
	var diffs []string
	for p, v := range after {
		if b, ok := before[p]; !ok {
			diffs = append(diffs, "created "+p)
		} else if b != v {
			diffs = append(diffs, "modified "+p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			diffs = append(diffs, "removed "+p)
		}
	}
	return diffs
}

// The operator subcommands (admin, runtime, agent) take only flags. Go's
// flag package stops at the first positional, so a stray word used to drop
// every later flag, including safety flags (--dry-run, --expected-sha256,
// --version pins, --policy-deny-codes). Each must refuse to run instead.
func TestOperatorSubcommandsRejectStrayPositional(t *testing.T) {
	cases := []struct {
		name string
		args func(w, validator string) []string
	}{
		{"admin list-tokens", func(w, _ string) []string {
			return []string{"admin", "list-tokens", "--workdir", w, "oops", "--json"}
		}},
		{"admin revoke-token", func(w, _ string) []string {
			return []string{"admin", "revoke-token", "--workdir", w, "--subject", "alice", "--tenant", "t1", "oops", "--dry-run"}
		}},
		{"admin verify-chain", func(w, _ string) []string {
			return []string{"admin", "verify-chain", "--workdir", w, "oops", "--json"}
		}},
		{"admin audit-export", func(w, _ string) []string {
			return []string{"admin", "audit-export", "--workdir", w, "oops", "--out", filepath.Join(w, "audit.ndjson")}
		}},
		{"admin audit-verify", func(w, _ string) []string {
			return []string{"admin", "audit-verify", "oops", "--input", filepath.Join(w, "a"), "--sig", filepath.Join(w, "b"), "--pubkey", filepath.Join(w, "c")}
		}},
		{"runtime select", func(w, _ string) []string {
			return []string{"runtime", "select", "--workdir", w, "--artifact-name", "demo", "--probe-use-sudo=false", "oops", "--policy-require-summary-pass", "--out", filepath.Join(w, "sel.json")}
		}},
		{"runtime fetch", func(w, _ string) []string {
			return []string{"runtime", "fetch", "--workdir", w, "--artifact-name", "demo", "--probe-use-sudo=false", "--out-dir", filepath.Join(w, "out"), "oops", "--version", "v1"}
		}},
		{"runtime execute", func(w, v string) []string {
			return []string{"runtime", "execute", "--workdir", w, "--artifact-name", "demo", "--allow-host-load", "--use-sudo=false", "--probe-use-sudo=false", "--validator", v, "--timeout", "10s", "--out-dir", filepath.Join(w, "out"), "oops", "--version", "v1", "--policy-deny-codes", "UNSUPPORTED_ATTACH_TYPE"}
		}},
		{"agent preflight", func(w, _ string) []string {
			return []string{"agent", "preflight", "--workdir", w, "--out-dir", filepath.Join(w, "o"), "--check-host-probe=false", "oops", "--require-config"}
		}},
		{"agent plan", func(w, _ string) []string {
			return []string{"agent", "plan", "--workdir", w, "--artifact-name", "demo", "--probe-use-sudo=false", "oops", "--api-url", "http://127.0.0.1:9", "--tenant", "t", "--project", "p", "--registry-token", "x"}
		}},
		{"agent apply", func(w, v string) []string {
			return []string{"agent", "apply", "--workdir", w, "--artifact-name", "demo", "--approve-load", "--require-load-policy=false", "--use-sudo=false", "--probe-use-sudo=false", "--validator", v, "--timeout", "10s", "--out-dir", filepath.Join(w, "out"), "oops", "--require-approval-pins", "--expected-decision-id", "reviewed-123", "--expected-sha256", strings.Repeat("0", 64)}
		}},
		{"agent status", func(w, _ string) []string {
			return []string{"agent", "status", "oops", "--path", filepath.Join(w, "missing.json")}
		}},
		{"agent ledger", func(w, _ string) []string {
			return []string{"agent", "ledger", "--workdir", w, "oops", "--json"}
		}},
		{"agent rollback", func(w, _ string) []string {
			return []string{"agent", "rollback", "--workdir", w, "--artifact-name", "demo", "oops", "--execute"}
		}},
		{"agent unload", func(w, _ string) []string {
			return []string{"agent", "unload", "--workdir", w, "--pin-path", filepath.Join(w, "pins", "p"), "--allow-non-bpffs", "oops", "--execute", "--record=false"}
		}},
		{"agent revocation-drill", func(w, _ string) []string {
			return []string{"agent", "revocation-drill", "--workdir", w, "oops", "--agent-id", "a"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := t.TempDir()
			// Defaults such as .bpfcompat and artifacts/... are relative to
			// the working directory; keep them inside the snapshot too.
			t.Chdir(w)
			seedDemoHistory(t, w)
			seedTokens(t, w, []cloudregistry.TokenGrant{
				{Subject: "alice", Tenant: "t1", Token: "tok-a"},
				{Subject: "bob", Tenant: "t1", Token: "tok-b"},
			})
			if err := os.MkdirAll(filepath.Join(w, "pins"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(w, "pins", "p"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			validator, _ := writeRecordingValidator(t, w)
			before := treeSnapshot(t, w)

			code, stdout, stderr := cliRun(t, tc.args(w, validator)...)

			if code != runner.ExitToolError {
				t.Errorf("exit %d, want %d (tool error)", code, runner.ExitToolError)
			}
			want := tc.name + `: unexpected positional argument "oops"`
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr does not contain %q:\n%s", want, stderr)
			}
			if stdout != "" {
				t.Errorf("a rejected command wrote to stdout:\n%s", stdout)
			}
			if diffs := diffSnapshots(before, treeSnapshot(t, w)); len(diffs) != 0 {
				t.Errorf("side effects from a rejected command:\n%s", strings.Join(diffs, "\n"))
			}
		})
	}
}

// A stray word before the approval pins must not turn a pinned, reviewed
// host load into an unpinned load of whatever the selector picks: the
// validator (the host-load step) must never run.
func TestAgentApplyStrayPositionalNeverInvokesValidator(t *testing.T) {
	common := func(w, validator string) []string {
		return []string{
			"agent", "apply", "--workdir", w, "--artifact-name", "demo",
			"--approve-load", "--require-load-policy=false",
			"--use-sudo=false", "--probe-use-sudo=false",
			"--validator", validator, "--timeout", "10s",
			"--out-dir", filepath.Join(w, "out"),
		}
	}

	// Control: the fixture really reaches the validator without the stray
	// word, so its absence below is meaningful.
	ctl := t.TempDir()
	t.Chdir(ctl)
	seedDemoHistory(t, ctl)
	ctlValidator, ctlLog := writeRecordingValidator(t, ctl)
	_, _, ctlStderr := cliRun(t, common(ctl, ctlValidator)...)
	if _, err := os.Stat(ctlLog); err != nil {
		t.Fatalf("control run did not reach the validator (fixture broken): %v\nstderr:\n%s", err, ctlStderr)
	}

	w := t.TempDir()
	t.Chdir(w)
	v1SHA := seedDemoHistory(t, w)
	validator, log := writeRecordingValidator(t, w)
	args := append(common(w, validator), "oops",
		"--require-approval-pins", "--expected-decision-id", "reviewed-123", "--expected-sha256", v1SHA)
	code, _, stderr := cliRun(t, args...)
	if body, err := os.ReadFile(log); err == nil {
		t.Errorf("validator was invoked despite the stray positional; argv:\n%s", body)
	}
	if code != runner.ExitToolError {
		t.Errorf("exit %d, want %d\nstderr:\n%s", code, runner.ExitToolError, stderr)
	}
}

// Likewise for runtime execute: a stray word before --version and
// --policy-deny-codes must not execute the newer, denied version.
func TestRuntimeExecuteStrayPositionalNeverInvokesValidator(t *testing.T) {
	common := func(w, validator string) []string {
		return []string{
			"runtime", "execute", "--workdir", w, "--artifact-name", "demo",
			"--allow-host-load", "--use-sudo=false", "--probe-use-sudo=false",
			"--validator", validator, "--timeout", "10s",
			"--out-dir", filepath.Join(w, "out"),
		}
	}

	ctl := t.TempDir()
	t.Chdir(ctl)
	seedDemoHistory(t, ctl)
	ctlValidator, ctlLog := writeRecordingValidator(t, ctl)
	_, _, ctlStderr := cliRun(t, common(ctl, ctlValidator)...)
	if _, err := os.Stat(ctlLog); err != nil {
		t.Fatalf("control run did not reach the validator (fixture broken): %v\nstderr:\n%s", err, ctlStderr)
	}

	w := t.TempDir()
	t.Chdir(w)
	seedDemoHistory(t, w)
	validator, log := writeRecordingValidator(t, w)
	args := append(common(w, validator), "oops", "--version", "v1", "--policy-deny-codes", "UNSUPPORTED_ATTACH_TYPE")
	code, _, stderr := cliRun(t, args...)
	if body, err := os.ReadFile(log); err == nil {
		t.Errorf("validator was invoked despite the stray positional; argv:\n%s", body)
	}
	if code != runner.ExitToolError {
		t.Errorf("exit %d, want %d\nstderr:\n%s", code, runner.ExitToolError, stderr)
	}
}

// A stray word before --dry-run must not perform a real revocation.
func TestAdminRevokeTokenStrayPositionalLeavesTokensUntouched(t *testing.T) {
	w := t.TempDir()
	t.Chdir(w)
	seedTokens(t, w, []cloudregistry.TokenGrant{
		{Subject: "alice", Tenant: "t1", Token: "tok-a"},
		{Subject: "bob", Tenant: "t1", Token: "tok-b"},
	})
	before, err := os.ReadFile(tokensPath(w))
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr := cliRun(t, "admin", "revoke-token", "--workdir", w, "--subject", "alice", "--tenant", "t1", "oops", "--dry-run")
	after, err := os.ReadFile(tokensPath(w))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("tokens.json changed despite the stray positional before --dry-run")
	}
	if code != runner.ExitToolError {
		t.Errorf("exit %d, want %d\nstderr:\n%s", code, runner.ExitToolError, stderr)
	}
}
