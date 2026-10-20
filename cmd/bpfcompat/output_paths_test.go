package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/runner"
)

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
// The pipe is drained concurrently so a chatty command cannot block on a full
// pipe buffer.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	defer func() {
		os.Stderr = old
	}()
	fn()
	_ = w.Close()
	os.Stderr = old
	out := <-done
	_ = r.Close()
	return string(out)
}

// discardStdout silences commands that print their payload to stdout.
func discardStdout(t *testing.T) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	old := os.Stdout
	os.Stdout = devnull
	t.Cleanup(func() {
		os.Stdout = old
		_ = devnull.Close()
	})
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func assertNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s not to be written (lstat err=%v)", path, err)
	}
}

// --- admin audit-export ----------------------------------------------------

// The signature envelope written over the export it signs leaves an operator
// with a "signed export" that is only a signature: the evidence is gone and
// the command used to exit 0.
func TestAuditExportRefusesSigOutOverOut(t *testing.T) {
	workDir := t.TempDir()
	seedAuditEvents(t, workDir)
	keyPath := writeEd25519KeyToFile(t)
	same := filepath.Join(t.TempDir(), "audit.ndjson")

	var code int
	stderr := captureStderr(t, func() {
		code = runAdminAuditExport([]string{
			"--workdir", workDir,
			"--out", same,
			"--sign-key", keyPath,
			"--sig-out", same,
		})
	})
	if code != runner.ExitToolError {
		t.Fatalf("audit-export --out == --sig-out exited %d, want %d; stderr=%s", code, runner.ExitToolError, stderr)
	}
	if !strings.Contains(stderr, "same file") {
		t.Fatalf("expected a same-file refusal, got stderr=%q", stderr)
	}
	// Refused before any side effect: nothing was written.
	assertNotExist(t, same)
}

// A second spelling of the same path (relative vs absolute, through a
// symlinked directory) is still the same file.
func TestAuditExportRefusesSigOutOverOutThroughSymlinkedDir(t *testing.T) {
	workDir := t.TempDir()
	seedAuditEvents(t, workDir)
	keyPath := writeEd25519KeyToFile(t)
	realDir := t.TempDir()
	linkDir := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	t.Chdir(realDir)

	var code int
	stderr := captureStderr(t, func() {
		code = runAdminAuditExport([]string{
			"--workdir", workDir,
			"--out", "audit.ndjson",
			"--sign-key", keyPath,
			"--sig-out", filepath.Join(linkDir, "audit.ndjson"),
		})
	})
	if code != runner.ExitToolError || !strings.Contains(stderr, "same file") {
		t.Fatalf("expected same-file refusal, got exit=%d stderr=%q", code, stderr)
	}
	assertNotExist(t, filepath.Join(realDir, "audit.ndjson"))
}

// The private signing key is an input; writing the export over it destroyed
// the key before it was read.
func TestAuditExportRefusesOutputOverSignKey(t *testing.T) {
	for _, flagName := range []string{"--out", "--sig-out"} {
		t.Run(flagName, func(t *testing.T) {
			workDir := t.TempDir()
			seedAuditEvents(t, workDir)
			keyPath := writeEd25519KeyToFile(t)
			before := mustReadFile(t, keyPath)
			other := filepath.Join(t.TempDir(), "other")
			args := []string{"--workdir", workDir, "--sign-key", keyPath}
			if flagName == "--out" {
				args = append(args, "--out", keyPath, "--sig-out", other)
			} else {
				args = append(args, "--out", other, "--sig-out", keyPath)
			}
			var code int
			stderr := captureStderr(t, func() { code = runAdminAuditExport(args) })
			if code != runner.ExitToolError || !strings.Contains(stderr, "same file") {
				t.Fatalf("expected same-file refusal, got exit=%d stderr=%q", code, stderr)
			}
			if after := mustReadFile(t, keyPath); !bytes.Equal(before, after) {
				t.Fatalf("signing key was modified")
			}
			assertNotExist(t, other)
		})
	}
}

// --- runtime fetch / execute ---------------------------------------------------

func seedRuntimeArtifact(t *testing.T) (workDir, artifactPath string) {
	t.Helper()
	workDir = t.TempDir()
	artifactPath = filepath.Join(workDir, "demo.bpf.o")
	artifactBytes := []byte{0x7f, 'E', 'L', 'F', 0x01, 0x02, 0x03}
	if err := os.WriteFile(artifactPath, artifactBytes, 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	sum := sha256.Sum256(artifactBytes)
	reportPath := filepath.Join(workDir, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"schema_version":"v0.1"}`), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := registry.PersistArtifactVersion(workDir, registry.ArtifactVersionRecord{
		RunID:           "run-1",
		ArtifactName:    "demo",
		ArtifactVersion: "v1",
		ArtifactPath:    artifactPath,
		ArtifactSHA256:  hex.EncodeToString(sum[:]),
		SummaryStatus:   "pass",
		RequiredPassed:  1,
		JSONReportPath:  reportPath,
	}); err != nil {
		t.Fatalf("persist artifact version: %v", err)
	}
	return workDir, artifactPath
}

// Control: distinct --out and fetched object both land intact.
func TestRuntimeFetchDistinctOutSucceeds(t *testing.T) {
	workDir, _ := seedRuntimeArtifact(t)
	outDir := filepath.Join(t.TempDir(), "o")
	outPath := filepath.Join(t.TempDir(), "fetch.json")
	discardStdout(t)
	if code := runRuntimeFetch([]string{
		"--workdir", workDir, "--artifact-name", "demo", "--version", "v1",
		"--out-dir", outDir, "--out", outPath,
	}); code != runner.ExitSuccess {
		t.Fatalf("control fetch exited %d", code)
	}
	if got := mustReadFile(t, filepath.Join(outDir, "demo-v1.o")); got[0] != 0x7f {
		t.Fatalf("fetched object is not the artifact")
	}
}

// --out naming the fetched object used to replace the verified artifact with
// the fetch JSON and exit 0.
func TestRuntimeFetchRefusesOutOverFetchedArtifact(t *testing.T) {
	cases := map[string]bool{"fresh out-dir": false, "object already fetched": true}
	for name, prefetch := range cases {
		t.Run(name, func(t *testing.T) {
			workDir, _ := seedRuntimeArtifact(t)
			outDir := filepath.Join(t.TempDir(), "o")
			target := filepath.Join(outDir, "demo-v1.o")
			if prefetch {
				discardStdout(t)
				if code := runRuntimeFetch([]string{
					"--workdir", workDir, "--artifact-name", "demo", "--version", "v1", "--out-dir", outDir,
				}); code != runner.ExitSuccess {
					t.Fatalf("prefetch exited %d", code)
				}
			}
			var code int
			stderr := captureStderr(t, func() {
				code = runRuntimeFetch([]string{
					"--workdir", workDir, "--artifact-name", "demo", "--version", "v1",
					"--out-dir", outDir, "--out", target,
				})
			})
			if code != runner.ExitToolError || !strings.Contains(stderr, "same file") {
				t.Fatalf("expected same-file refusal, got exit=%d stderr=%q", code, stderr)
			}
			if prefetch {
				if got := mustReadFile(t, target); got[0] != 0x7f {
					t.Fatalf("fetched object was overwritten: %q", got)
				}
			} else {
				// Refused before the fetch: nothing written.
				assertNotExist(t, outDir)
			}
		})
	}
}

// Relative --out against an absolute --out-dir is still the same file.
func TestRuntimeFetchRefusesRelativeOutOverFetchedArtifact(t *testing.T) {
	workDir, _ := seedRuntimeArtifact(t)
	base := t.TempDir()
	t.Chdir(base)
	var code int
	stderr := captureStderr(t, func() {
		code = runRuntimeFetch([]string{
			"--workdir", workDir, "--artifact-name", "demo", "--version", "v1",
			"--out-dir", filepath.Join(base, "o"), "--out", "./o/../o/demo-v1.o",
		})
	})
	if code != runner.ExitToolError || !strings.Contains(stderr, "same file") {
		t.Fatalf("expected same-file refusal, got exit=%d stderr=%q", code, stderr)
	}
	assertNotExist(t, filepath.Join(base, "o"))
}

// --out naming the registered local source artifact would overwrite the
// registry's copy of the object with JSON.
func TestRuntimeFetchRefusesOutOverSourceArtifact(t *testing.T) {
	workDir, artifactPath := seedRuntimeArtifact(t)
	before := mustReadFile(t, artifactPath)
	var code int
	stderr := captureStderr(t, func() {
		code = runRuntimeFetch([]string{
			"--workdir", workDir, "--artifact-name", "demo", "--version", "v1",
			"--out-dir", filepath.Join(t.TempDir(), "o"), "--out", artifactPath,
		})
	})
	if code != runner.ExitToolError || !strings.Contains(stderr, "same file") {
		t.Fatalf("expected same-file refusal, got exit=%d stderr=%q", code, stderr)
	}
	if after := mustReadFile(t, artifactPath); !bytes.Equal(before, after) {
		t.Fatalf("source artifact was modified")
	}
}

// runtime execute fetches through the same path and writes --out after the
// host run; the refusal must come before the fetch and the host load.
func TestRuntimeExecuteRefusesOutOverFetchedArtifact(t *testing.T) {
	workDir, _ := seedRuntimeArtifact(t)
	outDir := filepath.Join(t.TempDir(), "o")
	var code int
	stderr := captureStderr(t, func() {
		code = runRuntimeExecute([]string{
			"--workdir", workDir, "--artifact-name", "demo", "--version", "v1",
			"--allow-host-load", "--use-sudo=false", "--validator", "/bin/false",
			"--out-dir", outDir, "--out", filepath.Join(outDir, "demo-v1.o"),
		})
	})
	if code != runner.ExitToolError || !strings.Contains(stderr, "same file") {
		t.Fatalf("expected same-file refusal, got exit=%d stderr=%q", code, stderr)
	}
	assertNotExist(t, outDir)
}

// --- admin verify-chain --------------------------------------------------------

// A mistyped or missing --workdir used to print "verified 0 ... 0 invalid"
// and exit 0: a passing integrity check that checked nothing.
func TestAdminVerifyChainMissingWorkdirFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	for _, extra := range [][]string{nil, {"--json"}} {
		args := append([]string{"--workdir", missing}, extra...)
		var code int
		stderr := captureStderr(t, func() {
			stdout, restore := captureStdout(t)
			code = runAdminVerifyChain(args)
			_ = stdout.read()
			restore()
		})
		if code != runner.ExitToolError {
			t.Fatalf("verify-chain %v exited %d, want %d", args, code, runner.ExitToolError)
		}
		if !strings.Contains(stderr, missing) {
			t.Fatalf("expected the missing workdir in the error, got %q", stderr)
		}
	}
}

func TestAdminVerifyChainWorkdirIsFileFails(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var code int
	_ = captureStderr(t, func() { code = runAdminVerifyChain([]string{"--workdir", file}) })
	if code != runner.ExitToolError {
		t.Fatalf("verify-chain on a file exited %d, want %d", code, runner.ExitToolError)
	}
}

// An existing work directory with no history yet stays a success (see
// TestAdminVerifyChainEmpty), but it must say that nothing was verified.
func TestAdminVerifyChainEmptyWorkdirSaysNothingVerified(t *testing.T) {
	workDir := t.TempDir()
	var code int
	stderr := captureStderr(t, func() {
		stdout, restore := captureStdout(t)
		code = runAdminVerifyChain([]string{"--workdir", workDir})
		_ = stdout.read()
		restore()
	})
	if code != runner.ExitSuccess {
		t.Fatalf("verify-chain on empty existing workdir exited %d", code)
	}
	if !strings.Contains(stderr, "nothing was verified") {
		t.Fatalf("expected a nothing-verified note on stderr, got %q", stderr)
	}
}

// --- --out == --markdown (same helper as `diff`) ---------------------------------

func TestOutEqualsMarkdownRefused(t *testing.T) {
	dir := t.TempDir()
	same := filepath.Join(dir, "report")
	cases := map[string]func() int{
		"test": func() int {
			return runTest([]string{"--artifact", filepath.Join(dir, "a.bpf.o"), "--matrix", filepath.Join(dir, "m.yaml"), "--out", same, "--markdown", same})
		},
		"test-command": func() int {
			return runTestCommand([]string{"--cmd", "true", "--matrix", filepath.Join(dir, "m.yaml"), "--out", same, "--markdown", same})
		},
		"suite": func() int {
			return runSuite([]string{"--suite", filepath.Join(dir, "s.yaml"), "--out", same, "--markdown", same})
		},
		"compare": func() int {
			return runCompare([]string{"--base-report", filepath.Join(dir, "b.json"), "--head-report", filepath.Join(dir, "h.json"), "--out", same, "--markdown", same})
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			var code int
			stderr := captureStderr(t, func() { code = fn() })
			if code != runner.ExitToolError || !strings.Contains(stderr, "same file") {
				t.Fatalf("expected same-file refusal, got exit=%d stderr=%q", code, stderr)
			}
			assertNotExist(t, same)
		})
	}
}
