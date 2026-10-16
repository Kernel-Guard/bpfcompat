package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

var updateExecuteTargetGolden = flag.Bool("update-execute-target-golden", false,
	"rewrite testdata/execute_target_golden.json from the current executeTarget")

// executeTargetGoldenCase is one validator document run through the CLI's
// per-target path with a fixed VM execution result.
type executeTargetGoldenCase struct {
	name     string
	fx       attachFixture
	required bool
	profile  vm.Profile
	exec     vm.ExecutionResult // ValidatorResultPath, times filled in by the test
}

func executeTargetGoldenCases() []executeTargetGoldenCase {
	ubuntu := vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"}
	var cases []executeTargetGoldenCase
	for _, fx := range attachEvidenceFixtures() {
		cases = append(cases,
			executeTargetGoldenCase{name: fx.name + " [required]", fx: fx, required: true, profile: ubuntu},
			executeTargetGoldenCase{name: fx.name + " [optional]", fx: fx, required: false, profile: ubuntu},
		)
	}
	byName := map[string]attachFixture{}
	for _, fx := range attachEvidenceFixtures() {
		byName[fx.name] = fx
	}
	// The guest booted another kernel series and another distribution than
	// the profile requests: the environment block and mismatch note, and the
	// run-level INFRA_ERROR for a required target that otherwise passed.
	cases = append(cases, executeTargetGoldenCase{
		name: "wrong kernel and distro [required]", fx: byName["required all attached"], required: true,
		profile: vm.Profile{Distro: "rhel", Version: "8", KernelFamily: "4.18", Arch: "x86_64"},
		exec:    vm.ExecutionResult{GuestOSID: "ol", GuestOSVersionID: "9.4"},
	}, executeTargetGoldenCase{
		name: "wrong kernel, load failure [required]", fx: byName["load failure"], required: true,
		profile: vm.Profile{Distro: "rhel", Version: "8", KernelFamily: "4.18", Arch: "x86_64"},
	})
	// Executor notes and a non-fatal executor infra message must survive the
	// verdict computation on every branch.
	for _, n := range []string{"required all attached", "required mixed object", "load failure", "functional test failure", "unrecognized validator status"} {
		cases = append(cases, executeTargetGoldenCase{
			name: n + " [executor notes]", fx: byName[n], required: true, profile: ubuntu,
			exec: vm.ExecutionResult{Notes: []string{"executor: guest booted"}, InfraError: "executor: transient warning"},
		})
	}
	// Functional tests that passed contribute notes between the accounting
	// and the verdict notes.
	cases = append(cases, executeTargetGoldenCase{
		name: "functional test pass [required]", required: true, profile: ubuntu,
		fx: attachFixture{"functional test pass", "best-effort", nil, fakeAttach{mode: "best-effort", accounting: true, programCount: 1, records: 1,
			selected: 1, attachable: 1, attempted: 1, passed: 1, status: "pass", programs: tracingProgs("attached")},
			func(m map[string]any) {
				m["functional"] = map[string]any{"status": "pass", "tests": []map[string]any{
					{"name": "smoke", "required": true, "status": "pass", "exit_code": 0}}}
			}},
	}, executeTargetGoldenCase{
		name: "contradictory accounting with functional pass [required]", required: true, profile: ubuntu,
		fx: attachFixture{"contradictory accounting with functional pass", "required", nil, fakeAttach{mode: "required", accounting: true, programCount: 2, records: 2,
			selected: 2, attachable: 2, attempted: 2, passed: 2, status: "pass", programs: tracingProgs("attached", "failed")},
			func(m map[string]any) {
				m["functional"] = map[string]any{"status": "pass", "tests": []map[string]any{
					{"name": "smoke", "required": true, "status": "pass", "exit_code": 0}}}
			}},
	})
	return cases
}

type executeTargetGoldenEntry struct {
	Name string `json:"name"`
	// Inputs, so other frontends (pkg/bpfcompat) can replay the same
	// evidence and compare against the CLI's target.
	AttachMode       string          `json:"attach_mode"`
	RequiredPrograms []string        `json:"required_programs,omitempty"`
	Document         json.RawMessage `json:"validator_document"`
	Infra            bool            `json:"infra_error"`
	RequiredFail     bool            `json:"required_compat_failed"`
	RunVerdict       string          `json:"run_verdict"`
	Target           json.RawMessage `json:"target"`
}

func runExecuteTargetGolden(t *testing.T, c executeTargetGoldenCase) executeTargetGoldenEntry {
	t.Helper()
	dir := t.TempDir()
	vrPath := filepath.Join(dir, "result.json")
	doc := fixtureDoc(t, c.fx)
	if err := os.WriteFile(vrPath, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	stubProfile(t, c.profile)
	fixed := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		out := c.exec
		out.ProfileID = req.Profile.ID
		out.Status = "pass"
		out.ValidatorResultPath = vrPath
		out.StartedAt, out.FinishedAt = fixed, fixed.Add(1500*time.Millisecond)
		out.VMRunDir = "/run/vm"
		out.Notes = append([]string(nil), c.exec.Notes...)
		return out
	})
	required := c.required
	mp := matrix.MatrixProfile{ID: "golden-profile", Required: &required}
	target, infra, requiredFail := executeTarget(context.Background(), baseCfg(), mp, dir,
		"/tmp/a.bpf.o", "", "", validatorTuning{requiredAttachPrograms: c.fx.required}, "/tmp/validator", c.fx.mode)
	target.Verdict = schema.VerdictForStatus(target.Status)
	target.ValidatorResult = "$RUN/result.json"
	raw, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	return executeTargetGoldenEntry{
		Name: c.name, AttachMode: c.fx.mode, RequiredPrograms: c.fx.required, Document: doc,
		Infra: infra, RequiredFail: requiredFail,
		RunVerdict: schema.RunVerdict([]schema.Target{target}), Target: raw,
	}
}

// TestExecuteTargetGolden pins the CLI's per-target report bytes and return
// values for every evidence branch, so that moving the verdict computation
// into the shared evaluator is provably output-preserving. Regenerate only
// for an intended report change:
//
//	go test ./internal/runner -run TestExecuteTargetGolden -update-execute-target-golden
func TestExecuteTargetGolden(t *testing.T) {
	var entries []executeTargetGoldenEntry
	for _, c := range executeTargetGoldenCases() {
		entries = append(entries, runExecuteTargetGolden(t, c))
	}
	got, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "execute_target_golden.json")
	if *updateExecuteTargetGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update-execute-target-golden to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		var w []executeTargetGoldenEntry
		_ = json.Unmarshal(want, &w)
		for i := range entries {
			if i >= len(w) {
				t.Errorf("extra entry %q", entries[i].Name)
				continue
			}
			g, _ := json.Marshal(entries[i])
			ww, _ := json.Marshal(w[i])
			if !bytes.Equal(g, ww) {
				t.Errorf("entry %q differs:\n got  %s\n want %s", entries[i].Name, g, ww)
			}
		}
		if len(w) != len(entries) {
			t.Errorf("golden has %d entries, got %d", len(w), len(entries))
		}
	}
}
