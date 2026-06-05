package runner

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareRunCreatesExpectedDirectories(t *testing.T) {
	tempDir := t.TempDir()

	paths, err := PrepareRun(tempDir, time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("prepare run returned error: %v", err)
	}

	if !strings.HasPrefix(paths.RunID, "20260513T120000Z-") {
		t.Fatalf("unexpected run ID format: %s", paths.RunID)
	}
	if !strings.HasPrefix(paths.RunDir, filepath.Join(tempDir, "runs")) {
		t.Fatalf("unexpected run dir: %s", paths.RunDir)
	}
}
