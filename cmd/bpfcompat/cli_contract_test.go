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
