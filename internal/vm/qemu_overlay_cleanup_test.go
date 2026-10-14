package vm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installOverlayCleanupFakes puts fake qemu-img and qemu-system-x86_64
// binaries first on PATH so ExecuteProfile can be driven without a real VM.
// The fake qemu-img creates the overlay file and fails every resize.
func installOverlayCleanupFakes(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	img := `#!/bin/sh
case "$1" in
info) echo '{"format":"raw"}' ;;
create) for a; do last="$a"; done; : > "$last" ;;
resize) echo 'resize boom' >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "qemu-img"), []byte(img), 0o755); err != nil { // #nosec G306 -- test fake must be executable.
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "qemu-system-x86_64"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil { // #nosec G306 -- test fake must be executable.
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// A failed overlay resize must not leave overlay.qcow2 behind: the cleanup
// defer has to be registered as soon as the overlay exists.
func TestExecuteProfileRemovesOverlayWhenResizeFails(t *testing.T) {
	installOverlayCleanupFakes(t)

	base := filepath.Join(t.TempDir(), "base.img")
	if err := os.WriteFile(base, []byte("not-a-real-image"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := Profile{ID: "ubuntu-fake", Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"}
	p.Image.LocalPath = base

	runDir := t.TempDir()
	res := ExecuteProfile(context.Background(), ExecutionRequest{Profile: p, RunDir: runDir, Timeout: 2 * time.Second, DiskResizeGB: 2})
	if res.Status != "infra_error" || !strings.Contains(res.InfraError, "resize") {
		t.Fatalf("precondition: want resize infra_error, got status=%q infra=%q", res.Status, res.InfraError)
	}
	overlay := filepath.Join(runDir, "targets", p.ID, "overlay.qcow2")
	if _, err := os.Stat(overlay); err == nil {
		t.Fatalf("overlay leaked after resize failure: %s", overlay)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat overlay: %v", err)
	}

	// KeepVMOnFailure keeps the overlay for debugging, as before.
	runDir = t.TempDir()
	res = ExecuteProfile(context.Background(), ExecutionRequest{Profile: p, RunDir: runDir, Timeout: 2 * time.Second, DiskResizeGB: 2, KeepVMOnFailure: true})
	if !strings.Contains(res.InfraError, "resize") {
		t.Fatalf("precondition: want resize failure, got %q", res.InfraError)
	}
	if _, err := os.Stat(filepath.Join(runDir, "targets", p.ID, "overlay.qcow2")); err != nil {
		t.Fatalf("KeepVMOnFailure must keep the overlay: %v", err)
	}
}
