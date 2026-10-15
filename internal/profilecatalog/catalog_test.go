package profilecatalog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/vm"
)

const testProfile = `id: demo-1.0
distro: ubuntu
version: "1.0"
kernel_family: "5.15"
arch: x86_64
image:
  # keep me
  source_url: "https://example.invalid/demo.img"
  local_path: "vm/cache/demo.qcow2"
boot:
  memory_mb: 1024
  cpus: 1
validator:
  path: "/usr/local/bin/bpfcompat-validator"
capabilities:
  expected_btf: true
`

// isolate gives each test an empty CWD, a fake built-in catalog and clean env.
func isolate(t *testing.T, builtin fstest.MapFS) string {
	t.Helper()
	orig := builtinFS
	t.Cleanup(func() { builtinFS = orig })
	builtinFS = builtin
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv(EnvProfileDir, "")
	t.Setenv(EnvCacheDir, "")
	return dir
}

func builtinWith(id, body string) fstest.MapFS {
	return fstest.MapFS{"profiles/" + id + ".yaml": {Data: []byte(body)}}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPrecedenceEnvThenCheckoutThenBuiltin(t *testing.T) {
	cwd := isolate(t, builtinWith("demo-1.0", testProfile))

	loc, err := Locate("demo-1.0")
	if err != nil || loc.Source != SourceBuiltin {
		t.Fatalf("only built-in present: got %+v, %v", loc, err)
	}

	checkout := filepath.Join(cwd, "vm", "profiles", "demo-1.0.yaml")
	writeFile(t, checkout, testProfile)
	loc, err = Locate("demo-1.0")
	if err != nil || loc.Source != SourceCheckout || loc.Path != checkout {
		t.Fatalf("checkout should beat built-in: got %+v, %v", loc, err)
	}

	envDir := t.TempDir()
	envFile := filepath.Join(envDir, "demo-1.0.yaml")
	writeFile(t, envFile, testProfile)
	t.Setenv(EnvProfileDir, envDir)
	loc, err = Locate("demo-1.0")
	if err != nil || loc.Source != SourceEnvDir || loc.Path != envFile {
		t.Fatalf("env dir should beat checkout: got %+v, %v", loc, err)
	}
}

func TestExplicitEnvDirDoesNotFallBack(t *testing.T) {
	cwd := isolate(t, builtinWith("demo-1.0", testProfile))
	writeFile(t, filepath.Join(cwd, "vm", "profiles", "demo-1.0.yaml"), testProfile)
	envDir := t.TempDir()
	t.Setenv(EnvProfileDir, envDir)

	_, err := Locate("demo-1.0")
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("want NotFoundError, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{`profile "demo-1.0" not found`, EnvProfileDir + "=" + envDir, "no fallback"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing %q", msg, want)
		}
	}
}

func TestNotFoundNamesEverySearchedLocation(t *testing.T) {
	cwd := isolate(t, fstest.MapFS{})
	_, err := Resolve("ghost-9", t.TempDir())
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, want := range []string{
		`profile "ghost-9" not found`,
		"./vm/profiles/ghost-9.yaml",
		filepath.Join(cwd, "vm", "profiles", "ghost-9.yaml"),
		"built-in catalog",
		"set " + EnvProfileDir,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing %q", msg, want)
		}
	}
}

func TestInvalidIDsRejected(t *testing.T) {
	isolate(t, fstest.MapFS{})
	for _, id := range []string{"", ".", "..", "../etc/passwd", "a/b", `a\b`, "x..y"} {
		if _, err := Locate(id); err == nil || !strings.Contains(err.Error(), "invalid profile id") {
			t.Errorf("Locate(%q) = %v, want invalid profile id", id, err)
		}
	}
}

func TestBrokenCheckoutEntryDoesNotFallBackToBuiltin(t *testing.T) {
	cwd := isolate(t, builtinWith("demo-1.0", testProfile))
	// A directory where the profile file should be is a broken checkout, not
	// "absent": lookup must fail instead of quietly using the built-in copy.
	if err := os.MkdirAll(filepath.Join(cwd, "vm", "profiles", "demo-1.0.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Locate("demo-1.0"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("want not-a-regular-file error, got %v", err)
	}
}

func TestOnDiskProfilesAreUsedInPlace(t *testing.T) {
	cwd := isolate(t, fstest.MapFS{})
	checkout := filepath.Join(cwd, "vm", "profiles", "demo-1.0.yaml")
	writeFile(t, checkout, testProfile)
	stage := t.TempDir()
	got, err := Resolve("demo-1.0", stage)
	if err != nil || got != checkout {
		t.Fatalf("Resolve = %q, %v; want %q", got, err, checkout)
	}
	if entries, _ := os.ReadDir(stage); len(entries) != 0 {
		t.Fatalf("on-disk profile must not be staged, found %d entries", len(entries))
	}
}

func TestBuiltinProfileStagedWithImageUnderCacheRoot(t *testing.T) {
	isolate(t, builtinWith("demo-1.0", testProfile))
	cache := t.TempDir()
	t.Setenv(EnvCacheDir, cache)
	stage := t.TempDir()

	got, err := Resolve("demo-1.0", stage)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(stage, "profiles", "demo-1.0.yaml"); got != want {
		t.Fatalf("staged at %q, want %q", got, want)
	}
	p, err := vm.LoadProfile(got)
	if err != nil {
		t.Fatalf("staged profile does not load: %v", err)
	}
	if want := filepath.Join(cache, "vm", "cache", "demo.qcow2"); p.Image.LocalPath != want {
		t.Fatalf("image.local_path = %q, want %q", p.Image.LocalPath, want)
	}
	if p.Image.SourceURL != "https://example.invalid/demo.img" || p.ID != "demo-1.0" {
		t.Fatalf("other fields changed: %+v", p)
	}
	raw, _ := os.ReadFile(got)
	if !strings.Contains(string(raw), "# keep me") {
		t.Error("comments should survive the rewrite")
	}

	loc := Location{ID: "demo-1.0", Source: SourceBuiltin}
	if img, err := ImagePath(loc); err != nil || img != p.Image.LocalPath {
		t.Fatalf("ImagePath = %q, %v; want %q", img, err, p.Image.LocalPath)
	}

	// A second Resolve into the same stage dir must refuse to overwrite.
	if _, err := Resolve("demo-1.0", stage); err == nil || !errors.Is(err, os.ErrExist) {
		t.Fatalf("second staging should fail with ErrExist, got %v", err)
	}
}

func TestBuiltinAbsoluteImagePathUntouched(t *testing.T) {
	body := strings.Replace(testProfile, `"vm/cache/demo.qcow2"`, `"/srv/images/demo.qcow2"`, 1)
	isolate(t, builtinWith("demo-1.0", body))
	t.Setenv(EnvCacheDir, t.TempDir())
	got, err := Resolve("demo-1.0", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, err := vm.LoadProfile(got)
	if err != nil || p.Image.LocalPath != "/srv/images/demo.qcow2" {
		t.Fatalf("absolute local_path changed: %q, %v", p.Image.LocalPath, err)
	}
}

func TestCacheRootDefaultsToUserCacheDir(t *testing.T) {
	isolate(t, fstest.MapFS{})
	xdg := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", xdg)
	root, err := CacheRoot()
	if err != nil || root != filepath.Join(xdg, "bpfcompat") {
		t.Fatalf("CacheRoot = %q, %v", root, err)
	}
	t.Setenv(EnvCacheDir, "relative-cache")
	root, err = CacheRoot()
	if err != nil || !filepath.IsAbs(root) || filepath.Base(root) != "relative-cache" {
		t.Fatalf("CacheRoot with env = %q, %v", root, err)
	}
}

// TestBuiltinCatalogCoversRepoProfiles guards the embed: every profile in the
// source tree (and so every --quick ID) must be compiled in and loadable.
func TestBuiltinCatalogCoversRepoProfiles(t *testing.T) {
	onDisk, err := filepath.Glob(filepath.Join("..", "..", "vm", "profiles", "*.yaml"))
	if err != nil || len(onDisk) == 0 {
		t.Fatalf("glob repo profiles: %v (%d)", err, len(onDisk))
	}
	builtin := map[string]bool{}
	for _, id := range BuiltinIDs() {
		builtin[id] = true
	}
	for _, f := range onDisk {
		if id := strings.TrimSuffix(filepath.Base(f), ".yaml"); !builtin[id] {
			t.Errorf("vm/profiles/%s.yaml is not in the built-in catalog", id)
		}
	}
	isolate(t, nil) // switches CWD only; builtinFS restored below
	builtinFS = origBuiltin
	t.Setenv(EnvCacheDir, t.TempDir())
	for _, id := range matrix.QuickProfileIDs {
		got, err := Resolve(id, t.TempDir())
		if err != nil {
			t.Fatalf("--quick profile %s: %v", id, err)
		}
		if _, err := vm.LoadProfile(got); err != nil {
			t.Fatalf("--quick profile %s does not load from the built-in catalog: %v", id, err)
		}
	}
}

var origBuiltin = builtinFS
