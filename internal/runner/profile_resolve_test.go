package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/profilecatalog"
	"github.com/kernel-guard/bpfcompat/internal/vm"
)

// TestMain pins profile resolution to the historical CWD-relative path for
// this package's tests: their loadProfileFn stubs use made-up profile IDs
// ("ubuntu-test") that no catalog contains. Tests that exercise the real
// resolver swap profilecatalog.Resolve back in explicitly.
func TestMain(m *testing.M) {
	resolveProfileFn = func(id, _ string) (string, error) {
		return filepath.Join("vm", "profiles", id+".yaml"), nil
	}
	os.Exit(m.Run())
}

func useRealProfileResolver(t *testing.T) {
	t.Helper()
	orig, origLoad := resolveProfileFn, loadProfileFn
	t.Cleanup(func() { resolveProfileFn, loadProfileFn = orig, origLoad })
	resolveProfileFn = profilecatalog.Resolve
	t.Chdir(t.TempDir()) // no ./vm/profiles here
	t.Setenv(profilecatalog.EnvProfileDir, "")
	t.Setenv(profilecatalog.EnvCacheDir, t.TempDir())
}

func TestExecuteTargetUnknownProfileNamesSearchedLocations(t *testing.T) {
	useRealProfileResolver(t)
	loadProfileFn = func(string) (vm.Profile, error) {
		t.Fatal("loadProfileFn must not run for an unresolvable profile")
		return vm.Profile{}, nil
	}
	target, infraErr, _ := executeTarget(t.Context(), Config{Timeout: 1}, matrix.MatrixProfile{ID: "no-such-profile"},
		t.TempDir(), "", "", "", validatorTuning{}, "", "")
	if !infraErr || target.Status != "infra_error" || target.FailedStage != "infra" {
		t.Fatalf("want infra_error/infra, got status=%q stage=%q infra=%v", target.Status, target.FailedStage, infraErr)
	}
	for _, want := range []string{`profile "no-such-profile" not found`, "./vm/profiles/no-such-profile.yaml", "built-in catalog", profilecatalog.EnvProfileDir} {
		if !strings.Contains(target.InfraError, want) {
			t.Errorf("InfraError %q does not mention %q", target.InfraError, want)
		}
	}
}

func TestExecuteTargetUsesBuiltinProfileOutsideCheckout(t *testing.T) {
	useRealProfileResolver(t)
	runDir := t.TempDir()
	var loaded string
	loadProfileFn = func(p string) (vm.Profile, error) {
		loaded = p
		return vm.LoadProfile(p)
	}
	var image string
	orig := executeProfileFn
	t.Cleanup(func() { executeProfileFn = orig })
	executeProfileFn = func(_ context.Context, req vm.ExecutionRequest) vm.ExecutionResult {
		image = req.Profile.Image.LocalPath
		return vm.ExecutionResult{Status: "infra_error", InfraError: "stubbed executor"}
	}
	cacheRoot, err := profilecatalog.CacheRoot()
	if err != nil {
		t.Fatal(err)
	}
	id := matrix.QuickProfileIDs[0]
	target, infraErr, _ := executeTarget(t.Context(), Config{Timeout: 1}, matrix.MatrixProfile{ID: id},
		runDir, "", "", "", validatorTuning{}, "", "")
	if infraErr && strings.Contains(target.InfraError, "load profile") {
		t.Fatalf("built-in profile did not load: %s", target.InfraError)
	}
	if want := filepath.Join(runDir, "profiles", id+".yaml"); loaded != want {
		t.Fatalf("loaded %q, want the staged built-in copy %q", loaded, want)
	}
	if !strings.HasPrefix(image, filepath.Join(cacheRoot, "vm", "cache")+string(filepath.Separator)) {
		t.Fatalf("image.local_path %q not rebased under the cache root %q", image, cacheRoot)
	}
}
