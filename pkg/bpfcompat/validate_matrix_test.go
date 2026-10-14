package bpfcompat

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/runner"
)

// isolateTempDir points os.TempDir() at a fresh, test-owned directory so the
// tests can count exactly what Validate leaves behind.
func isolateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

func tempEntries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// stubBootstrap replaces the engine for the duration of the test. It returns a
// call counter and the last config the engine received.
func stubBootstrap(t *testing.T, fn func(context.Context, runner.Config) (runner.RunResult, error)) (*int, *runner.Config) {
	t.Helper()
	calls := 0
	var got runner.Config
	orig := executeBootstrapFn
	executeBootstrapFn = func(ctx context.Context, cfg runner.Config) (runner.RunResult, error) {
		calls++
		got = cfg
		return fn(ctx, cfg)
	}
	t.Cleanup(func() { executeBootstrapFn = orig })
	return &calls, &got
}

// fakeRun mimics the engine's on-disk side effects on success: a run directory
// under <WorkDir>/runs/<id> and a report at OutPath.
func fakeRun(_ context.Context, cfg runner.Config) (runner.RunResult, error) {
	runDir := filepath.Join(cfg.WorkDir, "runs", "fake-run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return runner.RunResult{}, err
	}
	if err := os.WriteFile(cfg.OutPath, []byte("{}"), 0o600); err != nil {
		return runner.RunResult{}, err
	}
	return runner.RunResult{RunDir: runDir}, nil
}

// A4-4: an engine failure must not leave the private workspace (or the temp
// report) behind — the caller never learns its path, so nobody could clean it.
// Uses the real engine: a missing artifact fails before any VM is booted.
func TestValidateRemovesPrivateWorkDirOnError(t *testing.T) {
	tmp := isolateTempDir(t)
	for i := 0; i < 3; i++ {
		_, err := Validate(context.Background(), Config{Artifact: filepath.Join(tmp, "missing.bpf.o"), Quick: true})
		if err == nil {
			t.Fatal("Validate with a missing artifact: want error, got nil")
		}
	}
	if left := tempEntries(t, tmp); len(left) != 0 {
		t.Fatalf("Validate returned an error but left %d entries in TMPDIR: %v", len(left), left)
	}
}

func TestValidateRemovesPrivateWorkDirOnEngineError(t *testing.T) {
	tmp := isolateTempDir(t)
	boom := errors.New("boom")
	stubBootstrap(t, func(ctx context.Context, cfg runner.Config) (runner.RunResult, error) {
		// Simulate an engine that got partway (run dir created) before failing.
		if _, err := fakeRun(ctx, cfg); err != nil {
			return runner.RunResult{}, err
		}
		return runner.RunResult{}, boom
	})
	if _, err := Validate(context.Background(), Config{Artifact: "x.bpf.o", Quick: true}); !errors.Is(err, boom) {
		t.Fatalf("Validate err = %v, want %v", err, boom)
	}
	if left := tempEntries(t, tmp); len(left) != 0 {
		t.Fatalf("Validate returned an error but left %d entries in TMPDIR: %v", len(left), left)
	}
}

// A4-4: on success the caller must be able to find and remove the private
// workspace Validate created; Report.RunDir alone (<root>/runs/<id>) is not
// enough.
func TestValidateSuccessCallerCanCleanUpPrivateWorkDir(t *testing.T) {
	tmp := isolateTempDir(t)
	stubBootstrap(t, fakeRun)

	rep, err := Validate(context.Background(), Config{Artifact: "x.bpf.o", Quick: true})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if rep.TempWorkDir == "" {
		t.Fatal("Report.TempWorkDir is empty for a Validate-created workspace")
	}
	if filepath.Dir(rep.TempWorkDir) != tmp {
		t.Fatalf("Report.TempWorkDir = %q, want a child of TMPDIR %q", rep.TempWorkDir, tmp)
	}
	if !strings.HasPrefix(rep.RunDir, rep.TempWorkDir+string(filepath.Separator)) {
		t.Fatalf("Report.RunDir %q is not inside Report.TempWorkDir %q", rep.RunDir, rep.TempWorkDir)
	}
	if _, err := os.Stat(rep.RunDir); err != nil {
		t.Fatalf("run dir must survive until Cleanup: %v", err)
	}
	if err := rep.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if left := tempEntries(t, tmp); len(left) != 0 {
		t.Fatalf("after Cleanup TMPDIR still has %d entries: %v", len(left), left)
	}
	if err := rep.Cleanup(); err != nil {
		t.Fatalf("second Cleanup must be a no-op, got %v", err)
	}
}

// A caller-supplied WorkDir is the caller's: Validate must not report it as
// temporary, and neither Cleanup nor an engine error may delete it.
func TestValidateCallerWorkDirIsNeverRemoved(t *testing.T) {
	isolateTempDir(t)
	work := t.TempDir()
	stubBootstrap(t, fakeRun)

	rep, err := Validate(context.Background(), Config{Artifact: "x.bpf.o", Quick: true, WorkDir: work})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if rep.TempWorkDir != "" {
		t.Fatalf("Report.TempWorkDir = %q, want empty for a caller-supplied WorkDir", rep.TempWorkDir)
	}
	if err := rep.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(rep.RunDir); err != nil {
		t.Fatalf("Cleanup removed the caller's workspace: %v", err)
	}

	stubBootstrap(t, func(context.Context, runner.Config) (runner.RunResult, error) {
		return runner.RunResult{}, errors.New("boom")
	})
	if _, err := Validate(context.Background(), Config{Artifact: "x.bpf.o", Quick: true, WorkDir: work}); err == nil {
		t.Fatal("want error")
	}
	if _, err := os.Stat(rep.RunDir); err != nil {
		t.Fatalf("Validate removed the caller's WorkDir on error: %v", err)
	}
}
