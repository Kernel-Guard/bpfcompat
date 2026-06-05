package vm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseExitCodeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "validator-exit-code")
	if err := os.WriteFile(path, []byte("2\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	code, err := parseExitCodeFile(path)
	if err != nil {
		t.Fatalf("parse exit code file: %v", err)
	}
	if code != 2 {
		t.Fatalf("expected 2, got %d", code)
	}
}
