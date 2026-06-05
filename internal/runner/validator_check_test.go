package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func compileTinyC(t *testing.T, source, outPath string, extraFlags ...string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("ELF static-link check only runs on linux")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skipf("cc not available: %v", err)
	}
	srcPath := filepath.Join(filepath.Dir(outPath), "tiny.c")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	args := append([]string{srcPath, "-o", outPath}, extraFlags...)
	cmd := exec.Command(cc, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cc compile failed (likely missing static libc): %v\n%s", err, string(out))
	}
}

func TestValidatorIsDynamicallyLinkedDetectsDynamicBuild(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "dyn")
	compileTinyC(t, "int main(void){return 0;}", bin)

	dynamic, err := validatorIsDynamicallyLinked(bin)
	if err != nil {
		t.Fatalf("inspect dynamic binary: %v", err)
	}
	if !dynamic {
		t.Fatalf("expected dynamic linkage detected for default cc build")
	}
}

func TestValidatorIsDynamicallyLinkedDetectsStaticBuild(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "stat")
	compileTinyC(t, "int main(void){return 0;}", bin, "-static")

	dynamic, err := validatorIsDynamicallyLinked(bin)
	if err != nil {
		t.Fatalf("inspect static binary: %v", err)
	}
	if dynamic {
		t.Fatalf("expected static binary, got dynamic-linkage signal")
	}
}

func TestValidatorIsDynamicallyLinkedRejectsNonELF(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "garbage")
	if err := os.WriteFile(bin, []byte("not-an-elf"), 0o644); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if _, err := validatorIsDynamicallyLinked(bin); err == nil {
		t.Fatalf("expected error parsing non-ELF file")
	}
}
