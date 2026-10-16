package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/freshness"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// --update-from-report must not record the kernel of a target that booted the
// wrong series, and must say so instead of dropping it silently.
func TestKernelFreshnessUpdateSkipsUnestablishedTarget(t *testing.T) {
	dir := t.TempDir()
	baselinesPath := filepath.Join(dir, "kernel-baselines.yaml")
	baselines := "baselines:\n" +
		"  - profile: ubuntu-22.04-5.15\n    kernel: 5.15.0-100-generic\n    recorded: \"2026-01-01\"\n" +
		"  - profile: ubuntu-24.04-6.8\n    kernel: 6.8.0-100-generic\n    recorded: \"2026-01-01\"\n"
	if err := os.WriteFile(baselinesPath, []byte(baselines), 0o600); err != nil {
		t.Fatal(err)
	}
	mismatch, match := false, true
	rep := schema.ReportV01{Run: schema.RunInfo{StartedAt: "2026-10-01T00:00:00Z"}, Targets: []schema.Target{
		{
			ProfileID: "ubuntu-22.04-5.15", Required: true, Status: "pass", Verdict: schema.VerdictCompatible,
			Host: &schema.TargetEnv{Kernel: "6.8.0-40-generic"},
			Environment: &schema.EnvironmentCheck{
				RequestedKernelFamily: "5.15", ObservedKernel: "6.8.0-40-generic", KernelFamilyMatch: &mismatch,
			},
		},
		{
			ProfileID: "ubuntu-24.04-6.8", Required: true, Status: "pass", Verdict: schema.VerdictCompatible,
			Host:        &schema.TargetEnv{Kernel: "6.8.0-130-generic"},
			Environment: &schema.EnvironmentCheck{RequestedKernelFamily: "6.8", KernelFamilyMatch: &match},
		},
	}}
	body, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(reportPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, restore := captureStdout(t)
	code := runKernelFreshness([]string{"--baselines", baselinesPath, "--update-from-report", reportPath})
	out := string(stdout.read())
	restore()
	if code != 0 {
		t.Fatalf("exit %d, output=%s", code, out)
	}
	wantSkip := "skipped ubuntu-22.04-5.15: did not establish requested environment (observed 6.8.0-40-generic)\n"
	if !strings.Contains(out, wantSkip) {
		t.Errorf("missing skip line %q in output:\n%s", wantSkip, out)
	}
	if !strings.Contains(out, "updated ubuntu-24.04-6.8\n") || strings.Contains(out, "updated ubuntu-22.04-5.15") {
		t.Errorf("unexpected update lines:\n%s", out)
	}

	data, err := os.ReadFile(baselinesPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := freshness.LoadBaselines(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range got.Baselines {
		switch entry.Profile {
		case "ubuntu-22.04-5.15":
			if entry.Kernel != "5.15.0-100-generic" {
				t.Errorf("wrong-series kernel recorded: %+v", entry)
			}
		case "ubuntu-24.04-6.8":
			if entry.Kernel != "6.8.0-130-generic" {
				t.Errorf("established target not recorded: %+v", entry)
			}
		}
	}
}
