package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/profilecatalog"
	"github.com/kernel-guard/bpfcompat/internal/runner"
)

const runAsCLIEnv = "BPFCOMPAT_TEST_RUN_AS_CLI"

// TestMain lets the compiled test binary act as the bpfcompat CLI, so the
// first-run tests below exercise a built binary (with its compiled-in profile
// catalog) started from a directory that is not a source checkout.
func TestMain(m *testing.M) {
	if os.Getenv(runAsCLIEnv) == "1" {
		os.Exit(run(os.Args[1:]))
	}
	os.Exit(m.Run())
}

type cliResult struct {
	exit           int
	stdout, stderr string
}

// runBuiltCLI runs the test binary as `bpfcompat args...` in dir with a
// minimal, hermetic environment (no inherited BPFCOMPAT_* settings).
func runBuiltCLI(t *testing.T, dir string, env []string, args ...string) cliResult {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, args...) // #nosec G204 -- the test binary itself.
	cmd.Dir = dir
	cmd.Env = append([]string{runAsCLIEnv + "=1", "HOME=" + dir}, env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run CLI: %v", err)
	}
	return cliResult{code, out.String(), errb.String()}
}

func TestFirstRunQuickResolvesBuiltinProfilesOutsideCheckout(t *testing.T) {
	fresh := t.TempDir()
	cache := t.TempDir()
	emptyPath := t.TempDir() // no qemu-img: each target stops right after profile + image resolution
	t.Setenv(profilecatalog.EnvCacheDir, cache)
	for _, id := range matrix.QuickProfileIDs {
		img, err := profilecatalog.ImagePath(profilecatalog.Location{ID: id, Source: profilecatalog.SourceBuiltin})
		if err != nil {
			t.Fatal(err)
		}
		writeFileT(t, img, "placeholder image")
	}

	res := runBuiltCLI(t, fresh, []string{"PATH=" + emptyPath, profilecatalog.EnvCacheDir + "=" + cache},
		"test", "--command", "true", "--quick", "--out", "report.json", "--timeout", "20s")
	if res.exit != runner.ExitToolError {
		t.Fatalf("exit=%d (want %d: infra error, no qemu-img)\nstdout:\n%s\nstderr:\n%s", res.exit, runner.ExitToolError, res.stdout, res.stderr)
	}
	raw, err := os.ReadFile(filepath.Join(fresh, "report.json"))
	if err != nil {
		t.Fatalf("report not written in the fresh dir: %v", err)
	}
	var rep struct {
		Targets []struct {
			ProfileID  string `json:"profile_id"`
			InfraError string `json:"infra_error"`
			VMRunDir   string `json:"vm_run_dir"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Targets) != len(matrix.QuickProfileIDs) {
		t.Fatalf("got %d targets", len(rep.Targets))
	}
	for _, tg := range rep.Targets {
		if strings.Contains(tg.InfraError, "profile") {
			t.Errorf("%s: profile resolution failed outside a checkout: %s", tg.ProfileID, tg.InfraError)
		}
		if !strings.Contains(tg.InfraError, "qemu-img") {
			t.Errorf("%s: expected to get as far as the qemu-img overlay step, got %q", tg.ProfileID, tg.InfraError)
		}
		// The built-in profile is staged as run evidence with the image rebased under the cache.
		runDir := filepath.Dir(filepath.Dir(tg.VMRunDir))
		staged, err := os.ReadFile(filepath.Join(fresh, runDir, "profiles", tg.ProfileID+".yaml"))
		if err != nil {
			staged, err = os.ReadFile(filepath.Join(runDir, "profiles", tg.ProfileID+".yaml"))
		}
		if err != nil {
			t.Fatalf("%s: staged profile missing: %v", tg.ProfileID, err)
		}
		if !strings.Contains(string(staged), filepath.Join(cache, "vm", "cache")) {
			t.Errorf("%s: staged profile does not point at the image cache:\n%s", tg.ProfileID, staged)
		}
	}
	if _, err := os.Stat(filepath.Join(fresh, "vm")); err == nil {
		t.Error("a run outside a checkout must not create ./vm in the working directory")
	}
}

func TestFirstRunMissingOutIsAClearError(t *testing.T) {
	res := runBuiltCLI(t, t.TempDir(), nil, "test", "--artifact", "probe.bpf.o", "--quick")
	if res.exit != runner.ExitToolError || !strings.Contains(res.stderr, "--out is required") {
		t.Fatalf("exit=%d stderr=%q", res.exit, res.stderr)
	}
}

func TestFirstRunExplicitProfileDirIsAuthoritative(t *testing.T) {
	fresh := t.TempDir()
	profiles := t.TempDir()
	res := runBuiltCLI(t, fresh, []string{profilecatalog.EnvProfileDir + "=" + profiles, "PATH=" + t.TempDir()},
		"doctor", "--command-mode")
	if res.exit != runner.ExitToolError {
		t.Fatalf("exit=%d, want %d\n%s", res.exit, runner.ExitToolError, res.stdout)
	}
	for _, id := range matrix.QuickProfileIDs {
		want := `profile "` + id + `" not found`
		if !strings.Contains(res.stdout, want) || !strings.Contains(res.stdout, profilecatalog.EnvProfileDir+"="+profiles) {
			t.Errorf("doctor output does not report %q with the searched dir:\n%s", want, res.stdout)
		}
	}
}

func TestDoctorReportsBuiltinProfilesAndMissingTools(t *testing.T) {
	fresh := t.TempDir()
	cache := t.TempDir()
	res := runBuiltCLI(t, fresh, []string{"PATH=" + t.TempDir(), profilecatalog.EnvCacheDir + "=" + cache}, "doctor", "--command-mode")
	if res.exit != runner.ExitToolError {
		t.Fatalf("exit=%d, want %d with no host tools on PATH\n%s", res.exit, runner.ExitToolError, res.stdout)
	}
	for _, want := range []string{
		"[FAIL] qemu-img", "install qemu-utils",
		"(builtin, from --quick set)",
		filepath.Join(cache, "vm", "cache"),
		"[ok  ] image cache",
		"problem(s) found",
	} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("doctor output missing %q:\n%s", want, res.stdout)
		}
	}
}

func writeFileT(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A relative image.local_path in a BPFCOMPAT_PROFILE_DIR profile resolves
// under the image cache root, so two unrelated working directories agree.
func TestFirstRunEnvDirImagePathIndependentOfWorkingDirectory(t *testing.T) {
	profiles := t.TempDir()
	src, err := os.ReadFile(filepath.Join("..", "..", "vm", "profiles", "debian-12-6.1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFileT(t, filepath.Join(profiles, "debian-12-6.1.yaml"), string(src))
	writeFileT(t, filepath.Join(profiles, "one.yaml"), "name: one\nprofiles:\n  - id: debian-12-6.1\n")
	cache := t.TempDir()
	want := filepath.Join(cache, "vm", "cache", "debian-12.qcow2")
	env := []string{profilecatalog.EnvProfileDir + "=" + profiles, profilecatalog.EnvCacheDir + "=" + cache, "PATH=" + t.TempDir()}
	for _, dir := range []string{t.TempDir(), t.TempDir()} {
		res := runBuiltCLI(t, dir, env, "doctor", "--command-mode", "--matrix", filepath.Join(profiles, "one.yaml"))
		if !strings.Contains(res.stdout, "(env, from ") || !strings.Contains(res.stdout, want) {
			t.Fatalf("from %s: doctor does not resolve the env-dir image under the cache (%s):\n%s", dir, want, res.stdout)
		}
		if !strings.Contains(res.stdout, "image digest not pinned") {
			t.Errorf("doctor should say the image is not pinned:\n%s", res.stdout)
		}
	}
}
