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

func TestStageDoesNotOverwriteExistingFile(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("new artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	stagedDir := filepath.Join(root, "staged")
	if err := os.Mkdir(stagedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(stagedDir, filepath.Base(source))
	if err := os.WriteFile(staged, []byte("existing artifact"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Stage(source, stagedDir); err == nil {
		t.Fatal("expected staging over an existing file to fail")
	}
	got, err := os.ReadFile(staged)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing artifact" {
		t.Fatalf("existing file was modified: %q", got)
	}
}

func TestStageDoesNotFollowDestinationSymlink(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("new artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	stagedDir := filepath.Join(root, "staged")
	if err := os.Mkdir(stagedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("protected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(stagedDir, filepath.Base(source))); err != nil {
		t.Fatal(err)
	}

	if _, err := Stage(source, stagedDir); err == nil {
		t.Fatal("expected staging over a destination symlink to fail")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "protected" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}
