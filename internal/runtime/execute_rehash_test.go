package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/registry"
)

const rehashPassJSON = `{"status":"pass","load":{"status":"pass"}}`

func rehashSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type rehashSeen struct {
	called   bool
	path     string
	sha      string
	dirPerm  os.FileMode
	filePerm os.FileMode
}

// fetchForRehash stages a genuine object through FetchArtifact into a
// group/other-writable out dir, like a shared default --out-dir.
func fetchForRehash(t *testing.T) (string, FetchResult) {
	t.Helper()
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.bpf.o")
	genuine := []byte{0x7f, 'E', 'L', 'F', 1}
	if err := os.WriteFile(src, genuine, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tmp, "out")
	fetched, err := FetchArtifact(registry.ArtifactVersionRecord{
		ArtifactName: "app", ArtifactVersion: "v1", ArtifactPath: src, ArtifactSHA256: rehashSHA(genuine),
	}, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(out, 0o777); err != nil {
		t.Fatal(err)
	}
	return tmp, fetched
}

func stubRehashValidator(t *testing.T, tmp string, onRun func(artifactArg string)) (string, *rehashSeen) {
	t.Helper()
	validator := filepath.Join(tmp, "validator")
	if err := os.WriteFile(validator, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	seen := &rehashSeen{}
	orig := runHostCommandFn
	t.Cleanup(func() { runHostCommandFn = orig })
	runHostCommandFn = func(cmd *exec.Cmd) error {
		seen.called = true
		seen.path = argValue(cmd.Args, "--artifact")
		if onRun != nil {
			onRun(seen.path)
		}
		b, err := os.ReadFile(seen.path)
		if err != nil {
			t.Errorf("validator read artifact: %v", err)
		}
		seen.sha = rehashSHA(b)
		if fi, err := os.Stat(seen.path); err == nil {
			seen.filePerm = fi.Mode().Perm()
		}
		if di, err := os.Stat(filepath.Dir(seen.path)); err == nil {
			seen.dirPerm = di.Mode().Perm()
		}
		return os.WriteFile(argValue(cmd.Args, "--out"), []byte(rehashPassJSON), 0o600)
	}
	return validator, seen
}

func rehashRequest(tmp, artifactPath, validator, expected string) ExecuteRequest {
	return ExecuteRequest{
		ArtifactPath: artifactPath, ArtifactRoot: filepath.Dir(artifactPath), ExpectedSHA256: expected, AttachMode: "best-effort", AllowHostLoad: true,
		ValidatorBinaryPath: validator, WorkDir: tmp, Timeout: 5 * time.Second,
	}
}

// SIGN-4: the staged copy is swapped after FetchArtifact verified it and
// before the validator loads it. Execution must refuse.
func TestExecuteArtifactOnHostRefusesArtifactSwappedAfterFetch(t *testing.T) {
	tmp, fetched := fetchForRehash(t)
	if err := os.WriteFile(fetched.OutputPath, []byte("SWAPPED-BY-ATTACKER"), 0o644); err != nil {
		t.Fatal(err)
	}
	validator, seen := stubRehashValidator(t, tmp, nil)
	_, err := ExecuteArtifactOnHost(context.Background(), rehashRequest(tmp, fetched.OutputPath, validator, fetched.ActualSHA256))
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch refusal, got err=%v (validator saw sha=%s)", err, seen.sha)
	}
	if seen.called {
		t.Fatalf("validator must not run on swapped bytes")
	}
}

func TestExecuteArtifactOnHostRefusesSymlinkedArtifact(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target []byte
	}{
		{name: "other_object", target: []byte("EVIL-OBJECT")},
		{name: "identical_bytes", target: []byte{0x7f, 'E', 'L', 'F', 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp, fetched := fetchForRehash(t)
			other := filepath.Join(tmp, "other.bpf.o")
			if err := os.WriteFile(other, tc.target, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(fetched.OutputPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, fetched.OutputPath); err != nil {
				t.Fatal(err)
			}
			validator, seen := stubRehashValidator(t, tmp, nil)
			_, err := ExecuteArtifactOnHost(context.Background(), rehashRequest(tmp, fetched.OutputPath, validator, fetched.ActualSHA256))
			if err == nil {
				t.Fatalf("expected symlinked artifact to be refused (validator saw sha=%s)", seen.sha)
			}
			if seen.called {
				t.Fatalf("validator must not run on a symlinked artifact")
			}
		})
	}
}

// The validator must load a private 0700 copy of the verified bytes, never
// the (possibly group/other-writable) staging path, so a racer that swaps
// the staged file while the validator runs cannot change what it loads.
func TestExecuteArtifactOnHostExecutesPrivateVerifiedCopy(t *testing.T) {
	tmp, fetched := fetchForRehash(t)
	validator, seen := stubRehashValidator(t, tmp, func(string) {
		if err := os.WriteFile(fetched.OutputPath, []byte("SWAPPED-DURING-EXEC"), 0o644); err != nil {
			t.Errorf("swap: %v", err)
		}
	})
	res, err := ExecuteArtifactOnHost(context.Background(), rehashRequest(tmp, fetched.OutputPath, validator, fetched.ActualSHA256))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Status != "pass" {
		t.Fatalf("expected pass, got %s", res.Status)
	}
	if seen.sha != fetched.ActualSHA256 {
		t.Fatalf("validator loaded sha=%s, want verified sha=%s", seen.sha, fetched.ActualSHA256)
	}
	if filepath.Dir(seen.path) == filepath.Dir(fetched.OutputPath) {
		t.Fatalf("validator was handed the shared staging dir %s", seen.path)
	}
	if seen.dirPerm != 0o700 {
		t.Fatalf("private exec dir mode=%#o, want 0700", seen.dirPerm)
	}
	if seen.filePerm&0o077 != 0 {
		t.Fatalf("private exec copy mode=%#o, must not be group/other accessible", seen.filePerm)
	}
	if res.ArtifactSHA256 != fetched.ActualSHA256 || res.ExpectedSHA256 != fetched.ActualSHA256 {
		t.Fatalf("result sha fields not recorded: %+v", res)
	}
	if _, err := os.Stat(filepath.Dir(seen.path)); !os.IsNotExist(err) {
		t.Fatalf("private exec dir must be removed after exec, stat err=%v", err)
	}
}

func TestExecuteArtifactOnHostRequiresExpectedSHA256(t *testing.T) {
	tmp, fetched := fetchForRehash(t)
	validator, seen := stubRehashValidator(t, tmp, nil)
	for _, expected := range []string{"", "not-a-digest"} {
		_, err := ExecuteArtifactOnHost(context.Background(), rehashRequest(tmp, fetched.OutputPath, validator, expected))
		if err == nil || !strings.Contains(err.Error(), "expected artifact sha256") {
			t.Fatalf("expected=%q: want expected-sha256 refusal, got %v", expected, err)
		}
	}
	if seen.called {
		t.Fatalf("validator must not run without an expected digest")
	}
}
