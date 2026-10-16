package runner

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/vm"
)

// Object (validator) mode must merge the executor's notes into the target the
// way command mode does: notes the runner already recorded on the target come
// first, then the executor's in order, then the validator-derived ones, with
// nothing dropped or repeated and without aliasing the executor's slice.
// Object mode used to replace target.Notes with the executor's notes, which
// silently drops any runner note added before execution (the per-target
// timeout note proposed in #225 is the first such note on the executing path).
func TestTargetNotesMergeExecutorNotesLikeCommandMode(t *testing.T) {
	resultPath := filepath.Join(t.TempDir(), "validator.json")
	writeValidatorResult(t, resultPath, map[string]any{
		"status": "pass",
		"host":   map[string]any{"release": "5.15.0-152-generic", "machine": "x86_64"},
		"load":   map[string]any{"status": "pass"},
	})
	stubProfile(t, vm.Profile{Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"})

	executorNotes := []string{"executor note one", "executor note two"}
	for _, mode := range []struct {
		name    string
		command string
	}{
		{"object", ""},
		{"command", "true"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			// Spare capacity: replacing target.Notes with this slice and then
			// appending writes runner notes into the executor's backing array.
			var execNotes []string
			stubExecutor(t, func(ctx context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
				now := time.Now().UTC()
				execNotes = make([]string, len(executorNotes), len(executorNotes)+8)
				copy(execNotes, executorNotes)
				notes := execNotes
				return vm.ExecutionResult{
					ProfileID: req.Profile.ID, Status: "pass", ValidatorResultPath: resultPath,
					CommandMode: mode.command != "", Notes: notes, StartedAt: now, FinishedAt: now,
				}
			})
			cfg := baseCfg()
			cfg.Command = mode.command

			notes := runOneTarget(t, cfg, "ubuntu-22.04-5.15", true)[0].Notes
			want := executorNotes
			if len(notes) < len(want) {
				t.Fatalf("notes = %q, want prefix %q", notes, want)
			}
			for i, w := range want {
				if notes[i] != w {
					t.Fatalf("notes = %q, want prefix %q", notes, want)
				}
			}
			if spill := execNotes[len(executorNotes) : len(executorNotes)+1][0]; spill != "" {
				t.Fatalf("runner appended %q into the executor's notes slice (target notes alias it)", spill)
			}
			seen := map[string]bool{}
			for _, n := range notes {
				if seen[n] {
					t.Fatalf("duplicate note %q in %q", n, notes)
				}
				seen[n] = true
			}
		})
	}
}
