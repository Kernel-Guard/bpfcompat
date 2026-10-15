package profilecatalog

import (
	"crypto/sha256"
	"encoding/hex"
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
	if err != nil || got.File != checkout || got.Source != SourceCheckout {
		t.Fatalf("Resolve = %+v, %v; want %q", got, err, checkout)
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

	res, err := Resolve("demo-1.0", stage)
	if err != nil {
		t.Fatal(err)
	}
	got := res.File
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
	res, err := Resolve("demo-1.0", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, err := vm.LoadProfile(res.File)
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
		if _, err := vm.LoadProfile(got.File); err != nil {
			t.Fatalf("--quick profile %s does not load from the built-in catalog: %v", id, err)
		}
	}
}

var origBuiltin = builtinFS

func sha(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// A dangling symlink at ./vm/profiles/<id>.yaml is a broken checkout, not an
// absent profile: os.Stat reports ENOENT for it, so lookup must use Lstat and
// refuse instead of quietly using the built-in copy.
func TestDanglingSymlinkDoesNotFallBackToBuiltin(t *testing.T) {
	cwd := isolate(t, builtinWith("demo-1.0", testProfile))
	dir := filepath.Join(cwd, "vm", "profiles")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(cwd, "missing-target.yaml"), filepath.Join(dir, "demo-1.0.yaml")); err != nil {
		t.Fatal(err)
	}
	_, err := Locate("demo-1.0")
	if err == nil || !strings.Contains(err.Error(), "dangling symlink") {
		t.Fatalf("want dangling symlink error, got %v", err)
	}
	if _, err := Resolve("demo-1.0", t.TempDir()); err == nil {
		t.Fatal("Resolve must fail too")
	}
}

func TestSymlinkToRegularFileIsUsed(t *testing.T) {
	cwd := isolate(t, fstest.MapFS{})
	target := filepath.Join(cwd, "elsewhere", "demo.yaml")
	writeFile(t, target, testProfile)
	dir := filepath.Join(cwd, "vm", "profiles")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "demo-1.0.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	loc, err := Locate("demo-1.0")
	if err != nil || loc.Source != SourceCheckout || loc.Path != link {
		t.Fatalf("got %+v, %v", loc, err)
	}
}

func TestResolvedRecordsSourcePathAndDigest(t *testing.T) {
	cwd := isolate(t, builtinWith("demo-1.0", testProfile))
	t.Setenv(EnvCacheDir, t.TempDir())

	// Built-in, no ./vm/profiles at all.
	res, err := Resolve("demo-1.0", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != SourceBuiltin || res.SHA256 != sha(testProfile) || res.CheckoutDirPresent {
		t.Fatalf("built-in resolution = %+v", res)
	}
	note := res.Note()
	for _, want := range []string{"profile source: built-in catalog", "sha256 " + sha(testProfile), res.File} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q missing %q", note, want)
		}
	}
	if strings.Contains(note, "./vm/profiles exists") {
		t.Errorf("no checkout dir, but note warns about one: %q", note)
	}

	// Built-in while ./vm/profiles exists but lacks the id: say so.
	if err := os.MkdirAll(filepath.Join(cwd, "vm", "profiles"), 0o750); err != nil {
		t.Fatal(err)
	}
	res, err = Resolve("demo-1.0", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !res.CheckoutDirPresent || !strings.Contains(res.Note(), "./vm/profiles exists but has no demo-1.0.yaml") {
		t.Fatalf("missing checkout-dir warning: %+v / %q", res, res.Note())
	}

	// Checkout.
	checkout := filepath.Join(cwd, "vm", "profiles", "demo-1.0.yaml")
	body := testProfile + "# local edit\n"
	writeFile(t, checkout, body)
	res, err = Resolve("demo-1.0", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != SourceCheckout || res.File != checkout || res.SHA256 != sha(body) {
		t.Fatalf("checkout resolution = %+v", res)
	}
	if n := res.Note(); !strings.Contains(n, "profile source: ./vm/profiles") || !strings.Contains(n, checkout) {
		t.Fatalf("checkout note = %q", n)
	}

	// Explicit env dir.
	envDir := t.TempDir()
	writeFile(t, filepath.Join(envDir, "demo-1.0.yaml"), testProfile)
	t.Setenv(EnvProfileDir, envDir)
	res, err = Resolve("demo-1.0", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if n := res.Note(); res.Source != SourceEnvDir || !strings.Contains(n, "profile source: "+EnvProfileDir) || !strings.Contains(n, envDir) {
		t.Fatalf("env resolution = %+v / %q", res, n)
	}
}
