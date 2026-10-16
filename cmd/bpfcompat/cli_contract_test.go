package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// cliRun runs the CLI in-process and returns its exit code, stdout and
// stderr. Both streams are drained concurrently so a large write to either
// cannot block on a full pipe.
func cliRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	drain := func(r *os.File) <-chan string {
		ch := make(chan string, 1)
		go func() {
			var sb strings.Builder
			buf := make([]byte, 32*1024)
			for {
				n, rerr := r.Read(buf)
				sb.Write(buf[:n])
				if rerr != nil {
					break
				}
			}
			ch <- sb.String()
		}()
		return ch
	}
	outCh, errCh := drain(outR), drain(errR)

	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	code := run(args)
	os.Stdout, os.Stderr = oldOut, oldErr

	_ = outW.Close()
	_ = errW.Close()
	stdout, stderr := <-outCh, <-errCh
	_ = outR.Close()
	_ = errR.Close()
	return code, stdout, stderr
}

func contractBool(v bool) *bool { return &v }

// writeContractReport writes a minimal, self-consistent v0.1 report.
func writeContractReport(t *testing.T, dir, name, runID string) string {
	t.Helper()
	targets := []schema.Target{{
		ProfileID: "ubuntu-22.04-5.15", Required: true, Status: "pass", Verdict: schema.VerdictCompatible,
		Environment: &schema.EnvironmentCheck{
			RequestedKernelFamily: "5.15",
			ObservedKernel:        "5.15.0-186-generic",
			KernelFamilyMatch:     contractBool(true),
		},
	}}
	report := schema.ReportV01{
		SchemaVersion: "v0.1",
		Run:           schema.RunInfo{ID: runID},
		Artifact:      schema.Artifact{SHA256: "aaa"},
		Targets:       targets,
		Summary: schema.SummaryInfo{
			Status:   "pass",
			Verdict:  schema.RunVerdict(targets),
			Complete: contractBool(schema.RunComplete(targets)),
		},
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// With neither --out nor --markdown, compare writes the diff JSON to stdout.
// stdout must then be exactly one JSON document (`bpfcompat compare ... | jq`
// must work); the human summary belongs on stderr, as with `diff`.
func TestCompareStdoutIsOneJSONDocument(t *testing.T) {
	dir := t.TempDir()
	base := writeContractReport(t, dir, "base.json", "r1")
	head := writeContractReport(t, dir, "head.json", "r2")

	code, stdout, stderr := cliRun(t, "compare", "--base-report", base, "--head-report", head)
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n---stdout---\n%s", err, stdout)
	}
	if _, ok := doc["summary"]; !ok {
		t.Fatalf("stdout JSON has no summary: %s", stdout)
	}
	if !strings.Contains(stderr, "Diff summary:") {
		t.Fatalf("human summary missing from stderr:\n%s", stderr)
	}
}

// When the JSON goes to a file, stdout is free for humans and keeps the
// summary there (unchanged behaviour).
func TestCompareSummaryStaysOnStdoutWithOut(t *testing.T) {
	dir := t.TempDir()
	base := writeContractReport(t, dir, "base.json", "r1")
	head := writeContractReport(t, dir, "head.json", "r2")
	out := filepath.Join(dir, "cmp.json")

	code, stdout, stderr := cliRun(t, "compare", "--base-report", base, "--head-report", head, "--out", out)
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "Compare JSON: "+out) || !strings.Contains(stdout, "Diff summary:") {
		t.Fatalf("stdout lacks the file notice or summary:\n%s", stdout)
	}
	body, err := os.ReadFile(out)
	if err != nil || !json.Valid(body) {
		t.Fatalf("--out is not valid JSON (err=%v):\n%s", err, body)
	}
}

// Go's flag package stops at the first non-flag argument, so a stray
// positional silently disables every flag after it. Each of these commands
// takes no positional arguments; a stray one must be a usage error that
// names the argument, exits non-zero, and does nothing else.
func TestSubcommandsRejectStrayPositional(t *testing.T) {
	dir := t.TempDir()
	base := writeContractReport(t, dir, "base.json", "r1")
	head := writeContractReport(t, dir, "head.json", "r2")
	workdir := filepath.Join(dir, "workdir")

	cases := []struct {
		name     string
		args     []string
		wantCode int
		// noFile must not exist after the run: the side effect a flag after
		// the stray positional would otherwise have produced.
		noFile string
	}{
		{
			name:     "diff",
			args:     []string{"diff", "--baseline", base, "--candidate", head, "stray", "--out", filepath.Join(dir, "diff.json")},
			wantCode: 1, // regressiondiff.ExitInconclusive: the comparison was not established
			noFile:   filepath.Join(dir, "diff.json"),
		},
		{
			name:     "compare",
			args:     []string{"compare", "--base-report", base, "--head-report", head, "stray", "--out", filepath.Join(dir, "cmp.json")},
			wantCode: 1,
			noFile:   filepath.Join(dir, "cmp.json"),
		},
		{
			name:     "compare-before-flags",
			args:     []string{"compare", "stray", "--base-report", base, "--head-report", head},
			wantCode: 1,
		},
		{
			name:     "history-list",
			args:     []string{"history", "list", "--workdir", workdir, "stray", "--json"},
			wantCode: 1,
			noFile:   workdir,
		},
		{
			name:     "history-verify",
			args:     []string{"history", "verify", "--workdir", workdir, "stray", "--json"},
			wantCode: 1,
			noFile:   workdir,
		},
		{
			name:     "history-sign",
			args:     []string{"history", "sign", "--workdir", workdir, "stray"},
			wantCode: 1,
			noFile:   workdir,
		},
		{
			name:     "profile-list",
			args:     []string{"profile", "list", "stray", "--matrix", filepath.Join(dir, "missing.yaml")},
			wantCode: 1,
		},
		{
			name:     "version",
			args:     []string{"version", "stray", "--json"},
			wantCode: 1,
		},
		{
			name:     "--version",
			args:     []string{"--version", "stray"},
			wantCode: 1,
		},
		{
			name:     "env",
			args:     []string{"env", "stray", "--json"},
			wantCode: 1,
		},
		{
			// An invalid --timeout precedes the stray argument so the base
			// code fails fast instead of binding a listener; the fix must
			// report the positional before validating anything else.
			name:     "serve",
			args:     []string{"serve", "--addr", "127.0.0.1:0", "--timeout", "not-a-duration", "stray"},
			wantCode: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := cliRun(t, tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.wantCode, stdout, stderr)
			}
			if !strings.Contains(stderr, `unexpected positional argument "stray"`) {
				t.Fatalf("stderr does not name the stray positional:\n%s", stderr)
			}
			if stdout != "" {
				t.Fatalf("a rejected command wrote to stdout:\n%s", stdout)
			}
			if tc.noFile != "" {
				if _, err := os.Stat(tc.noFile); !os.IsNotExist(err) {
					t.Fatalf("side effect: %s exists after a rejected command (stat err=%v)", tc.noFile, err)
				}
			}
		})
	}
}

// --help is still a successful request for help, not a positional error.
func TestSubcommandsHelpStillSucceeds(t *testing.T) {
	for _, args := range [][]string{
		{"diff", "--help"},
		{"compare", "--help"},
		{"history", "list", "--help"},
		{"profile", "list", "--help"},
		{"version", "--help"},
		{"env", "--help"},
		{"serve", "--help"},
	} {
		if code, _, stderr := cliRun(t, args...); code != 0 {
			t.Fatalf("%v: exit %d\n%s", args, code, stderr)
		}
	}
}

// compare writes --out and then --markdown; one file for both would leave
// Markdown where the caller asked for JSON. Like diff, it must refuse before
// writing anything, however the two paths are spelled.
func TestCompareRejectsSameOutAndMarkdown(t *testing.T) {
	dir := t.TempDir()
	base := writeContractReport(t, dir, "base.json", "r1")
	head := writeContractReport(t, dir, "head.json", "r2")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "same.json")

	for name, markdown := range map[string]string{
		"identical":  target,
		"respelled":  dir + "/sub/../same.json",
		"dot-prefix": dir + "/./same.json",
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := cliRun(t, "compare", "--base-report", base, "--head-report", head, "--out", target, "--markdown", markdown)
			if code != 1 {
				t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if !strings.Contains(stderr, "--out and --markdown are the same file") {
				t.Fatalf("stderr does not explain the refusal:\n%s", stderr)
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("compare wrote %s despite refusing (stat err=%v)", target, err)
			}
		})
	}

	// Distinct files are still accepted and each holds its own format.
	out, md := filepath.Join(dir, "cmp.json"), filepath.Join(dir, "cmp.md")
	if code, _, stderr := cliRun(t, "compare", "--base-report", base, "--head-report", head, "--out", out, "--markdown", md); code != 0 {
		t.Fatalf("distinct outputs: exit %d\n%s", code, stderr)
	}
	if body, err := os.ReadFile(out); err != nil || !json.Valid(body) {
		t.Fatalf("--out is not JSON (err=%v)", err)
	}
	if _, err := os.Stat(md); err != nil {
		t.Fatalf("--markdown not written: %v", err)
	}
}
