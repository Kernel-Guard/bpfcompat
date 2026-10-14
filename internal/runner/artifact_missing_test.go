package runner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExecuteBootstrapMissingArtifactPathIsLocalNotFound pins OCI-1 at the
// engine boundary every caller shares (CLI test/test-command, suite, API,
// pkg/bpfcompat.Validate): a missing local --artifact must fail with a local
// "no such file" error and must never reach the OCI loader (which would pull
// from Docker Hub and leak the path).
func TestExecuteBootstrapMissingArtifactPathIsLocalNotFound(t *testing.T) {
	orig := extractOCIFn
	t.Cleanup(func() { extractOCIFn = orig })
	extractOCIFn = func(_ context.Context, ref, _ string) (string, string, error) {
		t.Fatalf("OCI loader reached for missing local path %q (would contact a registry)", ref)
		return "", "", nil
	}

	missing := filepath.Join(t.TempDir(), "typo", "prog.bpf.o")
	for _, ref := range []string{"build/typo/prog.bpf.o", "./typo.bpf.o", "/nonexistent-bpfcompat-dir/prog.bpf.o", missing} {
		_, err := ExecuteBootstrap(context.Background(), Config{
			ArtifactPath: ref,
			Runner:       RunnerVM,
			Quick:        true,
			WorkDir:      t.TempDir(),
			Timeout:      time.Minute,
		})
		if err == nil {
			t.Fatalf("ExecuteBootstrap(%q): expected an error", ref)
		}
		want := `artifact "` + ref + `": no such file`
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("ExecuteBootstrap(%q) error = %q, want it to contain %q", ref, err, want)
		}
	}
}
