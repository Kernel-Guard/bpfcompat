package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStageCreatesPrivateFile(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("artifact"), 0o644); err != nil {
		t.Fatal(err)
	}

	staged, err := Stage(source, filepath.Join(root, "staged"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(staged)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected staged file mode 0600, got %o", info.Mode().Perm())
	}
}
