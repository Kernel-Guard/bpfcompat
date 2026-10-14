package api

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureRegularCompiledObjectRejectsNonRegular(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "host-secret")
	if err := os.WriteFile(secret, []byte("not-for-clients"), 0o600); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(dir, "regular.bpf.o")
	if err := os.WriteFile(regular, []byte("\x7fELF"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "compiled.bpf.o")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "dir.bpf.o")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := ensureRegularCompiledObject(regular); err != nil {
		t.Fatalf("regular object rejected: %v", err)
	}
	if err := ensureRegularCompiledObject(link); err == nil {
		t.Fatal("symlinked compiled object accepted; the server would follow it to a host file")
	}
	if err := ensureRegularCompiledObject(subdir); err == nil {
		t.Fatal("directory accepted as compiled object")
	}
	if err := ensureRegularCompiledObject(filepath.Join(dir, "missing.bpf.o")); err == nil {
		t.Fatal("missing compiled object accepted")
	}
}
