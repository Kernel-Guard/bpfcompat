package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// isolateExecTempDir points TMPDIR (where the private exec copy is staged)
// at an empty test dir and returns it. Call it after any t.TempDir use so
// the test's own temp dirs stay outside.
func isolateExecTempDir(t *testing.T, tmp string) string {
	t.Helper()
	dir := filepath.Join(tmp, "exec-tmpdir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", dir)
	return dir
}

func assertExecTempDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("leaked private exec dirs in TMPDIR: %v", names)
	}
}

func TestExecuteArtifactOnHostCleansPrivateDirOnShaMismatch(t *testing.T) {
	tmp, fetched := fetchForRehash(t)
	validator, seen := stubRehashValidator(t, tmp, nil)
	execTmp := isolateExecTempDir(t, tmp)
	if err := os.WriteFile(fetched.OutputPath, []byte("SWAPPED-BY-ATTACKER"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ExecuteArtifactOnHost(context.Background(), rehashRequest(tmp, fetched.OutputPath, validator, fetched.ActualSHA256))
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch, got %v", err)
	}
	if seen.called {
		t.Fatalf("validator must not run")
	}
	assertExecTempDirEmpty(t, execTmp)
}

func TestExecuteArtifactOnHostCleansPrivateDirOnNonRegularSource(t *testing.T) {
	tmp, fetched := fetchForRehash(t)
	validator, seen := stubRehashValidator(t, tmp, nil)
	execTmp := isolateExecTempDir(t, tmp)
	if err := os.Remove(fetched.OutputPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fetched.OutputPath, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := ExecuteArtifactOnHost(context.Background(), rehashRequest(tmp, fetched.OutputPath, validator, fetched.ActualSHA256))
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected non-regular refusal, got %v", err)
	}
	if seen.called {
		t.Fatalf("validator must not run")
	}
	assertExecTempDirEmpty(t, execTmp)
}

func TestExecuteArtifactOnHostCleansPrivateDirOnValidatorError(t *testing.T) {
	tmp, fetched := fetchForRehash(t)
	validator, _ := stubRehashValidator(t, tmp, nil)
	runHostCommandFn = func(*exec.Cmd) error { return errors.New("validator could not start") }
	execTmp := isolateExecTempDir(t, tmp)
	_, err := ExecuteArtifactOnHost(context.Background(), rehashRequest(tmp, fetched.OutputPath, validator, fetched.ActualSHA256))
	if err == nil || !strings.Contains(err.Error(), "validator could not start") {
		t.Fatalf("expected validator error, got %v", err)
	}
	assertExecTempDirEmpty(t, execTmp)
}

func TestExecuteArtifactOnHostCleansPrivateDirOnSuccess(t *testing.T) {
	tmp, fetched := fetchForRehash(t)
	validator, seen := stubRehashValidator(t, tmp, nil)
	execTmp := isolateExecTempDir(t, tmp)
	res, err := ExecuteArtifactOnHost(context.Background(), rehashRequest(tmp, fetched.OutputPath, validator, fetched.ActualSHA256))
	if err != nil || res.Status != "pass" {
		t.Fatalf("expected pass, got status=%s err=%v", res.Status, err)
	}
	if !strings.HasPrefix(seen.path, execTmp+string(filepath.Separator)) {
		t.Fatalf("private copy %s not staged under TMPDIR %s", seen.path, execTmp)
	}
	assertExecTempDirEmpty(t, execTmp)
}

// A FIFO swapped in for the staged file must be refused promptly, not block
// the open forever waiting for a writer.
func TestExecuteArtifactOnHostRefusesFIFOWithoutBlocking(t *testing.T) {
	tmp, fetched := fetchForRehash(t)
	validator, seen := stubRehashValidator(t, tmp, nil)
	execTmp := isolateExecTempDir(t, tmp)
	if err := os.Remove(fetched.OutputPath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fetched.OutputPath, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ExecuteArtifactOnHost(context.Background(), rehashRequest(tmp, fetched.OutputPath, validator, fetched.ActualSHA256))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected FIFO refusal, got %v", err)
		}
	case <-time.After(5 * time.Second):
		// Unblock the stuck reader so the goroutine can finish.
		if w, err := os.OpenFile(fetched.OutputPath, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close()
		}
		<-done
		t.Fatalf("opening a FIFO staged artifact blocked for >5s")
	}
	if seen.called {
		t.Fatalf("validator must not run")
	}
	assertExecTempDirEmpty(t, execTmp)
}
