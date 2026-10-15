package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/runner"
)

// --- dangling symlink outputs --------------------------------------------------

// An output given as a symlink to a path that does not exist yet used to be
// compared by the link's own path, so it never matched the not-yet-created
// file it writes through to.
func TestRefuseSameFileFollowsDanglingSymlinks(t *testing.T) {
	d := t.TempDir()
	future := filepath.Join(d, "future.json")
	abs := filepath.Join(d, "abs.json")
	mustSymlink(t, future, abs)
	rel := filepath.Join(d, "rel.json")
	mustSymlink(t, "future.json", rel)
	chain := filepath.Join(d, "chain.json")
	mustSymlink(t, "rel.json", chain)
	if err := os.Mkdir(filepath.Join(d, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	up := filepath.Join(d, "sub", "up.json")
	mustSymlink(t, filepath.Join("..", "future.json"), up)

	for name, link := range map[string]string{
		"absolute target": abs,
		"relative target": rel,
		"symlink chain":   chain,
		"dotdot target":   up,
	} {
		t.Run(name, func(t *testing.T) {
			if err := refuseSameFile("--out", link, "--other", future, "c"); err == nil {
				t.Fatalf("dangling symlink %s -> %s was not recognised as the same file", link, future)
			}
			// Symmetric: the link on either side.
			if err := refuseSameFile("--other", future, "--out", link, "c"); err == nil {
				t.Fatalf("dangling symlink %s not recognised when given second", link)
			}
		})
	}

	// Two dangling links to the same missing file are the same file too.
	if err := refuseSameFile("--a", abs, "--b", chain, "c"); err == nil {
		t.Fatalf("two dangling links to one missing file were not recognised")
	}
}

// A dangling symlink to a distinct file stays allowed, and a symlink loop
// terminates instead of hanging.
func TestRefuseSameFileDanglingSymlinkControls(t *testing.T) {
	d := t.TempDir()
	link := filepath.Join(d, "out.json")
	mustSymlink(t, filepath.Join(d, "elsewhere.json"), link)
	if err := refuseSameFile("--out", link, "--other", filepath.Join(d, "future.json"), "c"); err != nil {
		t.Fatalf("distinct dangling symlink refused: %v", err)
	}

	loopA, loopB := filepath.Join(d, "loopA"), filepath.Join(d, "loopB")
	mustSymlink(t, loopB, loopA)
	mustSymlink(t, loopA, loopB)
	if err := refuseSameFile("--out", loopA, "--other", filepath.Join(d, "future.json"), "c"); err != nil {
		t.Fatalf("symlink loop compared equal to an unrelated path: %v", err)
	}
}

// Reproduction from review: `runtime fetch --out L`, L a symlink to the
// not-yet-fetched object, exited 0 and the JSON replaced the fetched object.
func TestRuntimeFetchRefusesDanglingSymlinkOutToFetchedArtifact(t *testing.T) {
	workDir, _ := seedRuntimeArtifact(t)
	outDir := filepath.Join(t.TempDir(), "o")
	target := filepath.Join(outDir, "demo-v1.o")
	link := filepath.Join(t.TempDir(), "fetch.json")
	mustSymlink(t, target, link)
	var code int
	stderr := captureStderr(t, func() {
		code = runRuntimeFetch([]string{
			"--workdir", workDir, "--artifact-name", "demo", "--version", "v1",
			"--out-dir", outDir, "--out", link,
		})
	})
	if code != runner.ExitToolError || !strings.Contains(stderr, "same file") {
		t.Fatalf("expected same-file refusal, got exit=%d stderr=%q", code, stderr)
	}
	assertNotExist(t, target)
}

// Control: --out through a symlink to a distinct, not-yet-existing file still
// works, and the JSON lands at the link's target.
func TestRuntimeFetchSymlinkOutToDistinctFileSucceeds(t *testing.T) {
	workDir, _ := seedRuntimeArtifact(t)
	outDir := filepath.Join(t.TempDir(), "o")
	realOut := filepath.Join(t.TempDir(), "fetch.json")
	link := filepath.Join(t.TempDir(), "fetch-link.json")
	mustSymlink(t, realOut, link)
	discardStdout(t)
	if code := runRuntimeFetch([]string{
		"--workdir", workDir, "--artifact-name", "demo", "--version", "v1",
		"--out-dir", outDir, "--out", link,
	}); code != runner.ExitSuccess {
		t.Fatalf("fetch through a symlinked --out exited %d", code)
	}
	if got := mustReadFile(t, filepath.Join(outDir, "demo-v1.o")); got[0] != 0x7f {
		t.Fatalf("fetched object is not the artifact")
	}
	if got := mustReadFile(t, realOut); !strings.Contains(string(got), "{") {
		t.Fatalf("result JSON did not land at the symlink target: %q", got)
	}
}

func mustSymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Fatalf("symlink %s -> %s: %v", newname, oldname, err)
	}
}

// --- history verify --------------------------------------------------------------

// `history verify` on a missing work directory used to exit 0 ("No artifact
// history records found." or "[]"), unlike `admin verify-chain`.
func TestHistoryVerifyMissingWorkdirFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	for _, extra := range [][]string{nil, {"--json"}} {
		args := append([]string{"--workdir", missing}, extra...)
		var code int
		stderr := captureStderr(t, func() {
			stdout, restore := captureStdout(t)
			code = runHistoryVerify(args)
			_ = stdout.read()
			restore()
		})
		if code != runner.ExitToolError {
			t.Fatalf("history verify %v exited %d, want %d", args, code, runner.ExitToolError)
		}
		if !strings.Contains(stderr, missing) {
			t.Fatalf("expected the missing workdir in the error, got %q", stderr)
		}
	}
}

func TestHistoryVerifyWorkdirIsFileFails(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var code int
	stderr := captureStderr(t, func() {
		stdout, restore := captureStdout(t)
		code = runHistoryVerify([]string{"--workdir", file})
		_ = stdout.read()
		restore()
	})
	if code != runner.ExitToolError || !strings.Contains(stderr, "not a directory") {
		t.Fatalf("history verify on a file: exit=%d stderr=%q", code, stderr)
	}
}

// An existing work directory with no history stays a success, as for
// verify-chain, but says that nothing was verified.
func TestHistoryVerifyEmptyWorkdirSaysNothingVerified(t *testing.T) {
	for _, extra := range [][]string{nil, {"--json"}} {
		workDir := t.TempDir()
		args := append([]string{"--workdir", workDir}, extra...)
		var code int
		stderr := captureStderr(t, func() {
			stdout, restore := captureStdout(t)
			code = runHistoryVerify(args)
			_ = stdout.read()
			restore()
		})
		if code != runner.ExitSuccess {
			t.Fatalf("history verify %v on empty existing workdir exited %d", args, code)
		}
		if !strings.Contains(stderr, "nothing was verified") {
			t.Fatalf("expected a nothing-verified note on stderr, got %q", stderr)
		}
	}
}
