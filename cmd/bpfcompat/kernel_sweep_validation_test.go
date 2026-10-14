package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/internal/vm"
)

// Set BPFCOMPAT_UPDATE_KERNEL_SWEEP_GOLDEN=1 to rewrite the golden files
// under testdata/kernel-sweep (only do this deliberately).
const kernelSweepGoldenEnv = "BPFCOMPAT_UPDATE_KERNEL_SWEEP_GOLDEN"

type sweepRun struct {
	code        int
	profileDir  string
	matrixPath  string
	stderr      string
	baseProfile string
}

// runSweepFixture copies baseProfile from vm/profiles into a temp profile
// dir, writes inv as the crawler inventory, runs kernel-sweep with extra
// flags appended, and captures stderr.
func runSweepFixture(t *testing.T, baseProfile, series string, inv map[string][]map[string]any, extra ...string) sweepRun {
	t.Helper()
	dir := t.TempDir()
	profDir := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "vm", "profiles", baseProfile+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profDir, baseProfile+".yaml"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	invPath := filepath.Join(dir, "list.json")
	if err := os.WriteFile(invPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	mxPath := filepath.Join(dir, "matrix.yaml")
	args := []string{"kernel-sweep", "--profile", baseProfile, "--profile-dir", profDir,
		"--crawler-file", invPath, "--baselines", filepath.Join(dir, "none.yaml"), "--series", series,
		"--matrix-out", mxPath, "--count", "10"}
	args = append(args, extra...)

	outFile, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	errFile, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outFile, errFile
	code := run(args)
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = outFile.Close()
	_ = errFile.Close()
	stderr, _ := os.ReadFile(errFile.Name())
	return sweepRun{code: code, profileDir: profDir, matrixPath: mxPath,
		stderr: string(stderr), baseProfile: baseProfile}
}

func ubuntuEntry(release string) map[string]any {
	return map[string]any{
		"kernelrelease": release,
		"target":        "ubuntu-generic",
		"headers": []string{
			"http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-headers-" + release + "_5.15.0-999.1_amd64.deb",
		},
	}
}

func rockyEntry(release string) map[string]any {
	return map[string]any{
		"kernelrelease": release,
		"target":        "rocky",
		"headers": []string{
			"http://dl.rockylinux.org/pub/rocky/9.6/AppStream/x86_64/os/Packages/k/kernel-devel-" + release + ".rpm",
		},
	}
}

// generatedFiles returns the generated profiles (everything in the profile
// dir except the base) plus the matrix, keyed by output name.
func (r sweepRun) generatedFiles(t *testing.T) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	entries, err := os.ReadDir(r.profileDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == r.baseProfile+".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(r.profileDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files["profiles/"+e.Name()] = data
	}
	if data, err := os.ReadFile(r.matrixPath); err == nil {
		files["matrix.yaml"] = data
	}
	return files
}

// TestKernelSweepSkipsUnsafeReleases: kernelrelease comes from the
// network-fetched kernel-crawler inventory, so a crafted value must not be
// able to rewrite the generated matrix (flip required, add targets) or
// produce a profile the loader would reject.
func TestKernelSweepSkipsUnsafeReleases(t *testing.T) {
	injections := []string{
		"5.15.0-999\n    required: false\n  - id: injected-profile",
		"5.15.0-998\n  - id: injected-extra-item",
		"5.15.0-997 # comment",
		"5.15.0-996\"quoted\"",
		"5.15.0-995'single'",
		"5.15.0-994-gen\u00e9ric",
		"5.15.0-993\u2028injected-line-separator",
		"5.15.0-992: {required: false}",
		"5.15.0-991 required",
	}
	entries := []map[string]any{ubuntuEntry("5.15.0-118-generic")}
	for _, rel := range injections {
		entries = append(entries, ubuntuEntry(rel))
	}
	r := runSweepFixture(t, "ubuntu-22.04-5.15", "5.15.0-", map[string][]map[string]any{"ubuntu": entries})
	if r.code != runner.ExitSuccess {
		t.Fatalf("kernel-sweep exit %d, stderr:\n%s", r.code, r.stderr)
	}

	body, err := os.ReadFile(r.matrixPath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := matrix.Load(r.matrixPath)
	if err != nil {
		t.Fatalf("generated matrix does not load: %v\n%s", err, body)
	}
	if len(m.Profiles) != 1 || m.Profiles[0].ID != "ubuntu-22.04-5.15-k5.15.0-118" || !m.Profiles[0].RequiredBool() {
		t.Fatalf("matrix should hold only the legitimate release, got:\n%s", body)
	}
	for _, needle := range []string{"injected", "required: false", "comment", "quoted", "single", "\u00e9", "\u2028"} {
		if strings.Contains(string(body), needle) {
			t.Fatalf("matrix contains %q:\n%s", needle, body)
		}
	}

	files := r.generatedFiles(t)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	want := []string{"matrix.yaml", "profiles/ubuntu-22.04-5.15-k5.15.0-118.yaml"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("generated files = %q, want %q", names, want)
	}
	if _, err := vm.LoadProfile(filepath.Join(r.profileDir, "ubuntu-22.04-5.15-k5.15.0-118.yaml")); err != nil {
		t.Fatalf("generated profile does not load: %v", err)
	}

	for _, rel := range injections {
		if !strings.Contains(r.stderr, "skip "+strconv.Quote(rel)) {
			t.Errorf("stderr does not report skipping %q:\n%s", rel, r.stderr)
		}
	}
}

func TestKernelSweepAllReleasesUnsafeFails(t *testing.T) {
	inv := map[string][]map[string]any{"ubuntu": {
		ubuntuEntry("5.15.0-999\n    required: false\n  - id: injected-profile"),
	}}
	r := runSweepFixture(t, "ubuntu-22.04-5.15", "5.15.0-", inv)
	if r.code != runner.ExitToolError {
		t.Fatalf("kernel-sweep exit %d, want %d; stderr:\n%s", r.code, runner.ExitToolError, r.stderr)
	}
	if files := r.generatedFiles(t); len(files) != 0 {
		t.Fatalf("no files should be written, got %d", len(files))
	}
}

func TestKernelSweepRejectsInvalidTargetTimeout(t *testing.T) {
	inv := map[string][]map[string]any{"ubuntu": {ubuntuEntry("5.15.0-118-generic")}}
	for _, value := range []string{"20 minutes", "20m\n  - id: injected-profile", "", "0s", "-5m"} {
		t.Run(strconv.Quote(value), func(t *testing.T) {
			r := runSweepFixture(t, "ubuntu-22.04-5.15", "5.15.0-", inv, "--target-timeout", value)
			if r.code != runner.ExitToolError {
				t.Fatalf("kernel-sweep exit %d, want %d", r.code, runner.ExitToolError)
			}
			if !strings.Contains(r.stderr, "--target-timeout") {
				t.Fatalf("stderr does not name --target-timeout:\n%s", r.stderr)
			}
			if files := r.generatedFiles(t); len(files) != 0 {
				t.Fatalf("no files should be written, got %d", len(files))
			}
		})
	}
}

// TestKernelSweepGolden pins the generated matrix and profiles for normal
// Ubuntu and RHEL-family inventories byte-for-byte, so hardening the
// generator cannot silently change committed sweep output.
func TestKernelSweepGolden(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		series  string
		inv     map[string][]map[string]any
		extra   []string
	}{
		{
			name:    "ubuntu",
			profile: "ubuntu-22.04-5.15",
			series:  "5.15.0-",
			inv: map[string][]map[string]any{"ubuntu": {
				ubuntuEntry("5.15.0-118-generic"),
				ubuntuEntry("5.15.0-119-generic"),
				ubuntuEntry("5.15.0-1060-generic"),
			}},
			extra: []string{"--target-timeout", "25m"},
		},
		{
			name:    "rocky",
			profile: "rocky-9-5.14",
			series:  "5.14.0-",
			inv: map[string][]map[string]any{"rocky": {
				rockyEntry("5.14.0-687.26.1.el9_8.x86_64"),
				rockyEntry("5.14.0-687.36.1.el9_8.x86_64"),
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := runSweepFixture(t, tc.profile, tc.series, tc.inv, tc.extra...)
			if r.code != runner.ExitSuccess {
				t.Fatalf("kernel-sweep exit %d, stderr:\n%s", r.code, r.stderr)
			}
			got := r.generatedFiles(t)
			goldenDir := filepath.Join("testdata", "kernel-sweep", tc.name)
			if os.Getenv(kernelSweepGoldenEnv) == "1" {
				_ = os.RemoveAll(goldenDir)
				for name, data := range got {
					path := filepath.Join(goldenDir, filepath.FromSlash(name))
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, data, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				return
			}
			want := map[string][]byte{}
			err := filepath.WalkDir(goldenDir, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				data, err := os.ReadFile(path) // #nosec G304,G122 -- test golden files
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(goldenDir, path)
				if err != nil {
					return err
				}
				want[filepath.ToSlash(rel)] = data
				return nil
			})
			if err != nil {
				t.Fatalf("read golden dir: %v", err)
			}
			if len(want) == 0 {
				t.Fatalf("no golden files in %s", goldenDir)
			}
			for name, data := range want {
				if string(got[name]) != string(data) {
					t.Errorf("%s differs from golden:\n--- got ---\n%s\n--- want ---\n%s", name, got[name], data)
				}
			}
			for name := range got {
				if _, ok := want[name]; !ok {
					t.Errorf("unexpected generated file %s", name)
				}
			}
		})
	}
}
