package runner

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erenari/bpfcompat/internal/matrix"
	"github.com/erenari/bpfcompat/internal/vm"
)

func TestExecuteTargetsHonorsConcurrencyAndOrder(t *testing.T) {
	origLoadProfileFn := loadProfileFn
	origExecuteProfileFn := executeProfileFn
	t.Cleanup(func() {
		loadProfileFn = origLoadProfileFn
		executeProfileFn = origExecuteProfileFn
	})

	loadProfileFn = func(path string) (vm.Profile, error) {
		return vm.Profile{ID: filepath.Base(path)}, nil
	}

	var current int32
	var maxConcurrent int32
	executeProfileFn = func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		n := atomic.AddInt32(&current, 1)
		for {
			seen := atomic.LoadInt32(&maxConcurrent)
			if n <= seen {
				break
			}
			if atomic.CompareAndSwapInt32(&maxConcurrent, seen, n) {
				break
			}
		}

		time.Sleep(80 * time.Millisecond)
		atomic.AddInt32(&current, -1)

		now := time.Now().UTC()
		return vm.ExecutionResult{
			ProfileID:  req.Profile.ID,
			Status:     "infra_error",
			InfraError: "simulated infra error",
			StartedAt:  now.Add(-80 * time.Millisecond),
			FinishedAt: now,
		}
	}

	cfg := Config{
		Concurrency:     2,
		Timeout:         2 * time.Second,
		KeepVMOnFailure: false,
	}
	m := matrix.Matrix{
		Profiles: []matrix.MatrixProfile{
			{ID: "p1"},
			{ID: "p2"},
			{ID: "p3"},
			{ID: "p4"},
		},
	}

	start := time.Now()
	targets, _, hasInfraError, hasRequiredCompatFailure := executeTargets(
		context.Background(),
		cfg,
		m,
		t.TempDir(),
		"/tmp/a.bpf.o",
		"",
		"",
		"/tmp/validator",
		"best-effort",
		nil,
	)
	elapsed := time.Since(start)

	if !hasInfraError {
		t.Fatalf("expected infra error summary from mocked executor")
	}
	if hasRequiredCompatFailure {
		t.Fatalf("did not expect compatibility failure summary")
	}
	if len(targets) != 4 {
		t.Fatalf("unexpected target count: got=%d want=4", len(targets))
	}

	if max := atomic.LoadInt32(&maxConcurrent); max < 2 {
		t.Fatalf("expected concurrent execution, max concurrent=%d", max)
	}
	if max := atomic.LoadInt32(&maxConcurrent); max > 2 {
		t.Fatalf("expected concurrency limit 2, got max concurrent=%d", max)
	}
	if elapsed >= 280*time.Millisecond {
		t.Fatalf("expected batched execution faster than sequential; elapsed=%s", elapsed)
	}

	if targets[0].ProfileID != "p1" || targets[1].ProfileID != "p2" ||
		targets[2].ProfileID != "p3" || targets[3].ProfileID != "p4" {
		t.Fatalf("target order did not match matrix order: %#v", targets)
	}
}

func TestExecuteTargetsMarksUnsupportedTransportAsCompatibilityFailure(t *testing.T) {
	origLoadProfileFn := loadProfileFn
	origExecuteProfileFn := executeProfileFn
	t.Cleanup(func() {
		loadProfileFn = origLoadProfileFn
		executeProfileFn = origExecuteProfileFn
	})

	loadProfileFn = func(path string) (vm.Profile, error) {
		return vm.Profile{
			ID:           filepath.Base(path),
			Distro:       "talos",
			Version:      "1.12",
			KernelFamily: "6.6",
			Arch:         "x86_64",
		}, nil
	}
	executeProfileFn = func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		t.Fatalf("executeProfileFn should not be called for unsupported transport profiles")
		return vm.ExecutionResult{}
	}

	cfg := Config{
		Concurrency: 1,
		Timeout:     2 * time.Second,
	}
	m := matrix.Matrix{
		Profiles: []matrix.MatrixProfile{
			{ID: "talos-optional", Required: boolPtr(false)},
			{ID: "talos-required", Required: boolPtr(true)},
		},
	}

	targets, _, hasInfraError, hasRequiredCompatFailure := executeTargets(
		context.Background(),
		cfg,
		m,
		t.TempDir(),
		"/tmp/a.bpf.o",
		"",
		"",
		"/tmp/validator",
		"best-effort",
		nil,
	)

	if hasInfraError {
		t.Fatalf("did not expect infra error for unsupported transport compatibility classification")
	}
	if !hasRequiredCompatFailure {
		t.Fatalf("expected required compatibility failure for required unsupported transport profile")
	}
	if len(targets) != 2 {
		t.Fatalf("unexpected target count: got=%d want=2", len(targets))
	}
	for _, target := range targets {
		if target.Status != "fail" {
			t.Fatalf("expected fail status, got %q", target.Status)
		}
		if target.FailedStage != "transport" {
			t.Fatalf("expected failed_stage transport, got %q", target.FailedStage)
		}
		if target.ClassificationCode != "UNSUPPORTED_TRANSPORT" {
			t.Fatalf("expected UNSUPPORTED_TRANSPORT classification, got %q", target.ClassificationCode)
		}
	}
}

func TestExecuteTargetClassifiesFunctionalFailure(t *testing.T) {
	origLoadProfileFn := loadProfileFn
	origExecuteProfileFn := executeProfileFn
	t.Cleanup(func() {
		loadProfileFn = origLoadProfileFn
		executeProfileFn = origExecuteProfileFn
	})

	loadProfileFn = func(path string) (vm.Profile, error) {
		return vm.Profile{
			ID:           "ubuntu-test",
			Distro:       "ubuntu",
			Version:      "22.04",
			KernelFamily: "5.15",
			Arch:         "x86_64",
		}, nil
	}

	executeProfileFn = func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		resultPath := filepath.Join(req.RunDir, "validator-result.json")
		if err := os.MkdirAll(filepath.Dir(resultPath), 0o755); err != nil {
			t.Fatalf("mkdir result: %v", err)
		}
		raw := `{
  "schema_version": "validator.v0.4",
  "status": "fail",
  "host": {"release": "5.15.0-test", "machine": "x86_64"},
  "load": {"status": "pass", "error_code": 0, "error": ""},
  "attach": {"mode": "required", "status": "pass", "attempted": 1, "passed": 1, "failed": 0},
  "functional": {
    "status": "fail",
    "tests": [
      {"name": "capture-events", "required": true, "status": "fail", "command": "./expect-events.sh", "timeout_seconds": 30, "expected_exit_code": 0, "exit_code": 1, "error": "events=0"}
    ]
  },
  "btf": {"kernel_btf_available": true, "artifact_has_btf": true, "artifact_has_btf_ext": true}
}`
		if err := os.WriteFile(resultPath, []byte(raw), 0o644); err != nil {
			t.Fatalf("write result: %v", err)
		}
		now := time.Now().UTC()
		return vm.ExecutionResult{
			ProfileID:           req.Profile.ID,
			Status:              "pass",
			ValidatorResultPath: resultPath,
			StartedAt:           now.Add(-time.Second),
			FinishedAt:          now,
		}
	}

	target, infraErr, requiredFail := executeTarget(
		context.Background(),
		Config{Timeout: 2 * time.Second},
		matrix.MatrixProfile{ID: "ubuntu-test", Required: boolPtr(true)},
		t.TempDir(),
		"/tmp/a.bpf.o",
		"",
		"/tmp/functional-plan.txt",
		"/tmp/validator",
		"required",
	)

	if infraErr {
		t.Fatalf("did not expect infra error: %+v", target)
	}
	if !requiredFail {
		t.Fatalf("expected required compatibility failure")
	}
	if target.Status != "fail" || target.FailedStage != "functional" {
		t.Fatalf("unexpected target status/stage: %+v", target)
	}
	if target.ClassificationCode != "FUNCTIONAL_TEST_FAILURE" {
		t.Fatalf("expected FUNCTIONAL_TEST_FAILURE, got %q", target.ClassificationCode)
	}
	if target.Functional == nil || target.Functional.Status != "fail" || len(target.Functional.Tests) != 1 {
		t.Fatalf("functional result not surfaced: %+v", target.Functional)
	}
}

func boolPtr(v bool) *bool {
	return &v
}
