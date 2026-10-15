// Package profilecatalog finds VM profile files by ID.
//
// Lookup order (first match wins):
//
//  1. $BPFCOMPAT_PROFILE_DIR/<id>.yaml when BPFCOMPAT_PROFILE_DIR is set. An
//     explicit directory is authoritative: if the profile is not there, lookup
//     fails instead of silently falling through to another catalog.
//  2. ./vm/profiles/<id>.yaml relative to the current directory (a source
//     checkout or the GitHub Action, which runs from its own checkout). This is
//     the historical behavior and stays byte-for-byte unchanged.
//  3. The built-in catalog compiled into the binary (vm/profiles at build time).
//
// Profiles from 1 and 2 are used in place, so a relative image.local_path keeps
// resolving against the current directory exactly as before. A built-in
// profile is written into the run's own directory with a relative
// image.local_path rebased under the image cache root ($BPFCOMPAT_CACHE_DIR,
// default $XDG_CACHE_HOME/bpfcompat or ~/.cache/bpfcompat), so an installed CLI
// keeps one shared image cache instead of downloading into whatever directory
// it was started from.
package profilecatalog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	vmcatalog "github.com/kernel-guard/bpfcompat/vm"
)

const (
	// EnvProfileDir names a directory of <id>.yaml profiles that takes
	// precedence over every other location.
	EnvProfileDir = "BPFCOMPAT_PROFILE_DIR"
	// EnvCacheDir is the image cache root for built-in profiles.
	EnvCacheDir = "BPFCOMPAT_CACHE_DIR"
	// CheckoutDir is the CWD-relative profile directory of a source checkout.
	CheckoutDir = "vm/profiles"
)

// Source says where a profile was found.
type Source string

const (
	SourceEnvDir   Source = "env"      // $BPFCOMPAT_PROFILE_DIR
	SourceCheckout Source = "checkout" // ./vm/profiles
	SourceBuiltin  Source = "builtin"  // compiled into the binary
)

// Location is a side-effect-free lookup result.
type Location struct {
	ID     string
	Source Source
	// Path is the on-disk file for SourceEnvDir/SourceCheckout (absolute), or
	// "builtin:profiles/<id>.yaml" for SourceBuiltin.
	Path string
}

// builtinFS is the catalog used for SourceBuiltin; tests replace it.
var builtinFS fs.FS = vmcatalog.Profiles

// NotFoundError reports a profile that is in none of the searched locations.
type NotFoundError struct {
	ID       string
	Searched []string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("profile %q not found; searched: %s (set %s to a directory containing %s.yaml)",
		e.ID, strings.Join(e.Searched, "; "), EnvProfileDir, e.ID)
}

func validateID(id string) error {
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
		return fmt.Errorf("invalid profile id %q", id)
	}
	return nil
}

// Locate finds profile id without touching the filesystem beyond stat calls.
func Locate(id string) (Location, error) {
	if err := validateID(id); err != nil {
		return Location{}, err
	}
	file := id + ".yaml"

	if dir := strings.TrimSpace(os.Getenv(EnvProfileDir)); dir != "" {
		abs, err := filepath.Abs(filepath.Join(dir, file))
		if err != nil {
			return Location{}, fmt.Errorf("resolve %s: %w", EnvProfileDir, err)
		}
		if ok, err := profileFileExists(abs); err != nil {
			return Location{}, err
		} else if ok {
			return Location{ID: id, Source: SourceEnvDir, Path: abs}, nil
		}
		return Location{}, &NotFoundError{ID: id, Searched: []string{
			fmt.Sprintf("%s=%s (%s; explicit directory, no fallback)", EnvProfileDir, dir, abs),
		}}
	}

	searched := make([]string, 0, 2)
	checkout, err := filepath.Abs(filepath.Join(CheckoutDir, file))
	if err != nil {
		return Location{}, fmt.Errorf("resolve profile path: %w", err)
	}
	if ok, err := profileFileExists(checkout); err != nil {
		return Location{}, err
	} else if ok {
		return Location{ID: id, Source: SourceCheckout, Path: checkout}, nil
	}
	searched = append(searched, fmt.Sprintf("./%s/%s (%s)", CheckoutDir, file, checkout))

	if _, err := fs.Stat(builtinFS, path.Join("profiles", file)); err == nil {
		return Location{ID: id, Source: SourceBuiltin, Path: "builtin:profiles/" + file}, nil
	}
	searched = append(searched, fmt.Sprintf("built-in catalog (%d profiles compiled into this binary)", BuiltinCount()))
	return Location{}, &NotFoundError{ID: id, Searched: searched}
}

// Resolve returns a profile file path that vm.LoadProfile can read. On-disk
// profiles are returned in place. A built-in profile is written to
// stageDir/profiles/<id>.yaml (stageDir is the run directory, so the file is
// also run evidence) with its relative image.local_path rebased under
// CacheRoot().
func Resolve(id, stageDir string) (string, error) {
	loc, err := Locate(id)
	if err != nil {
		return "", err
	}
	if loc.Source != SourceBuiltin {
		return loc.Path, nil
	}
	data, err := fs.ReadFile(builtinFS, path.Join("profiles", id+".yaml"))
	if err != nil {
		return "", fmt.Errorf("read built-in profile %q: %w", id, err)
	}
	root, err := CacheRoot()
	if err != nil {
		return "", err
	}
	data, err = rebaseImagePath(data, root)
	if err != nil {
		return "", fmt.Errorf("built-in profile %q: %w", id, err)
	}
	dir := filepath.Join(stageDir, "profiles")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("stage built-in profile %q: %w", id, err)
	}
	out := filepath.Join(dir, id+".yaml")
	// O_EXCL: never overwrite an existing file, even inside the run dir.
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- runner-owned run directory; id validated above.
	if err != nil {
		return "", fmt.Errorf("stage built-in profile %q: %w", id, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("stage built-in profile %q: %w", id, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("stage built-in profile %q: %w", id, err)
	}
	return out, nil
}

// CacheRoot is where built-in profiles keep their images: $BPFCOMPAT_CACHE_DIR,
// else <user cache dir>/bpfcompat. A built-in image.local_path such as
// "vm/cache/debian-12.qcow2" lands at <root>/vm/cache/debian-12.qcow2, so
// pointing BPFCOMPAT_CACHE_DIR at a source checkout reuses its vm/cache.
func CacheRoot() (string, error) {
	if dir := strings.TrimSpace(os.Getenv(EnvCacheDir)); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", EnvCacheDir, err)
		}
		return abs, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no image cache directory for built-in profiles (%w); set %s", err, EnvCacheDir)
	}
	return filepath.Join(base, "bpfcompat"), nil
}

// BuiltinIDs lists the profile IDs compiled into the binary, sorted.
func BuiltinIDs() []string {
	entries, err := fs.ReadDir(builtinFS, "profiles")
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if name := e.Name(); !e.IsDir() && strings.HasSuffix(name, ".yaml") {
			ids = append(ids, strings.TrimSuffix(name, ".yaml"))
		}
	}
	return ids
}

// BuiltinCount is len(BuiltinIDs()).
func BuiltinCount() int { return len(BuiltinIDs()) }

// ImagePath returns the image.local_path a profile resolved by Resolve would
// use, as an absolute path (for diagnostics such as `bpfcompat doctor`).
func ImagePath(loc Location) (string, error) {
	var data []byte
	var err error
	if loc.Source == SourceBuiltin {
		data, err = fs.ReadFile(builtinFS, path.Join("profiles", loc.ID+".yaml"))
	} else {
		data, err = os.ReadFile(loc.Path)
	}
	if err != nil {
		return "", err
	}
	var p struct {
		Image struct {
			LocalPath string `yaml:"local_path"`
		} `yaml:"image"`
	}
	if err := yaml.Unmarshal(data, &p); err != nil {
		return "", err
	}
	local := p.Image.LocalPath
	if local == "" || filepath.IsAbs(local) {
		return local, nil
	}
	if loc.Source == SourceBuiltin {
		root, err := CacheRoot()
		if err != nil {
			return "", err
		}
		return filepath.Join(root, local), nil
	}
	return filepath.Abs(local)
}

// rebaseImagePath rewrites a relative image.local_path to root/local_path,
// leaving every other node (and comments) as is.
func rebaseImagePath(data []byte, root string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse profile YAML: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, errors.New("profile YAML is empty")
	}
	image := mappingValue(doc.Content[0], "image")
	if image == nil {
		return data, nil
	}
	local := mappingValue(image, "local_path")
	if local == nil || local.Kind != yaml.ScalarNode || local.Value == "" || filepath.IsAbs(local.Value) {
		return data, nil
	}
	local.Value = filepath.Join(root, filepath.FromSlash(local.Value))
	local.Style = yaml.DoubleQuotedStyle
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("render profile YAML: %w", err)
	}
	return out, nil
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// profileFileExists reports whether p is a profile file. Only "does not
// exist" lets lookup move on to the next location; any other stat failure (or
// a non-regular file) is an error, so a broken checkout never silently falls
// back to the built-in catalog.
func profileFileExists(p string) (bool, error) {
	info, err := os.Stat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("stat profile %s: %w", p, err)
	case !info.Mode().IsRegular():
		return false, fmt.Errorf("profile %s is not a regular file", p)
	}
	return true, nil
}
