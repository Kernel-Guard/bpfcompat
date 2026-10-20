package vm

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const earlyExitQEMUMessage = "qemu-system-x86_64: could not set up host forwarding rule 'tcp:127.0.0.1:2222-:22'"

// installEarlyExitFakes puts fake qemu-img, qemu-system-x86_64 and (when
// sshScript is non-empty) ssh binaries first on PATH so ExecuteProfile can be
// driven without a real VM.
func installEarlyExitFakes(t *testing.T, qemuScript, sshScript string) {
	t.Helper()
	dir := t.TempDir()
	img := `#!/bin/sh
case "$1" in
info) echo '{"format":"raw"}' ;;
create) for a; do last="$a"; done; : > "$last" ;;
resize) exit 0 ;;
esac
`
	fakes := map[string]string{"qemu-img": img, "qemu-system-x86_64": qemuScript}
	if sshScript != "" {
		fakes["ssh"] = sshScript
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil { // #nosec G306 -- test fake must be executable.
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func earlyExitProfile(t *testing.T) Profile {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
	base := filepath.Join(t.TempDir(), "base.img")
	if err := os.WriteFile(base, []byte("not-a-real-image"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := Profile{ID: "ubuntu-fake", Distro: "ubuntu", Version: "22.04", KernelFamily: "5.15", Arch: "x86_64"}
	p.Image.LocalPath = base
	return p
}

// A QEMU that dies on launch (port clash, bad accel, missing firmware) must
// end the SSH wait at once and surface qemu.log, not burn the whole timeout
// and report an SSH timeout.
func TestExecuteProfileReportsEarlyQEMUExit(t *testing.T) {
	installEarlyExitFakes(t, "#!/bin/sh\necho \""+earlyExitQEMUMessage+"\" >&2\nexit 1\n", "")
	p := earlyExitProfile(t)

	start := time.Now()
	res := ExecuteProfile(context.Background(), ExecutionRequest{Profile: p, RunDir: t.TempDir(), Timeout: 10 * time.Second})
	elapsed := time.Since(start)
	t.Logf("elapsed=%s infra=%q", elapsed, res.InfraError)

	if res.Status != "infra_error" {
		t.Fatalf("status=%q, want infra_error", res.Status)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("early QEMU exit took %s to report (SSH timeout 10s): %q", elapsed, res.InfraError)
	}
	for _, want := range []string{"qemu exited before SSH was ready", "exit status 1", earlyExitQEMUMessage} {
		if !strings.Contains(res.InfraError, want) {
			t.Fatalf("infra error %q does not contain %q", res.InfraError, want)
		}
	}
}

// The same detection applies to the SSH wait after the kernel-install reboot:
// the first QEMU boots and "reboots" (exits) on request, the relaunched QEMU
// dies at once.
func TestExecuteProfileReportsEarlyQEMUExitAfterKernelInstallReboot(t *testing.T) {
	state := t.TempDir()
	t.Setenv("BPFCOMPAT_FAKE_STATE", state)
	qemu := `#!/bin/sh
s="$BPFCOMPAT_FAKE_STATE"
if [ ! -e "$s/launched" ]; then
	: > "$s/launched"
	: > "$s/running"
	i=0
	while [ ! -e "$s/reboot" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done
	rm -f "$s/running"
	exit 0
fi
echo "` + earlyExitQEMUMessage + `" >&2
exit 1
`
	ssh := `#!/bin/sh
s="$BPFCOMPAT_FAKE_STATE"
for a; do last="$a"; done
[ -e "$s/running" ] || { echo "ssh: connect to host 127.0.0.1: Connection refused" >&2; exit 255; }
case "$last" in
printf*) printf '__BPFCOMPAT_OK__' ;;
*) if grep -q 'systemctl reboot'; then : > "$s/reboot"; fi ;;
esac
exit 0
`
	installEarlyExitFakes(t, qemu, ssh)
	p := earlyExitProfile(t)
	p.InstallKernel = "5.15.0-1-generic"

	start := time.Now()
	res := ExecuteProfile(context.Background(), ExecutionRequest{Profile: p, RunDir: t.TempDir(), Timeout: 20 * time.Second})
	elapsed := time.Since(start)
	t.Logf("elapsed=%s infra=%q notes=%q", elapsed, res.InfraError, res.Notes)

	if res.Status != "infra_error" {
		t.Fatalf("status=%q, want infra_error", res.Status)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("early QEMU exit after reboot took %s to report (SSH timeout 20s): %q", elapsed, res.InfraError)
	}
	for _, want := range []string{"after kernel-install reboot", "qemu exited before SSH was ready", earlyExitQEMUMessage} {
		if !strings.Contains(res.InfraError, want) {
			t.Fatalf("infra error %q does not contain %q", res.InfraError, want)
		}
	}
}

// waitProcessExit and terminate share the single cmd.Wait owned by the
// instance: running both concurrently must not call Wait twice (the race
// detector flags that), and done must close even for a QEMU that ignores
// SIGTERM.
func TestQEMUInstanceSingleWaitTerminateAndWaitExit(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command("/bin/sh", "-c", `trap '' TERM; : > "$1"; while :; do sleep 0.1; done`, "fake-qemu", ready) // #nosec G204 -- fixed test script.
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	q := newQEMUInstance(cmd)
	for i := 0; ; i++ {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if i == 100 {
			q.terminate()
			t.Fatal("fake qemu never became ready")
		}
		time.Sleep(20 * time.Millisecond)
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- waitProcessExit(q, 30*time.Second) }()
	start := time.Now()
	q.terminate()
	if d := time.Since(start); d < qemuTerminateGrace {
		t.Fatalf("terminate returned after %s; SIGTERM-ignoring process should need SIGKILL after %s", d, qemuTerminateGrace)
	}

	select {
	case <-q.done:
	default:
		t.Fatal("terminate returned before the QEMU process was reaped")
	}
	if err := <-waitErr; err != nil {
		t.Fatalf("waitProcessExit: %v", err)
	}
	if q.err == nil || strings.Contains(q.err.Error(), "Wait was already called") {
		t.Fatalf("exit error = %v, want the SIGKILL exit from the single Wait", q.err)
	}
	// terminate after exit is a no-op that returns at once.
	start = time.Now()
	q.terminate()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("terminate on an exited instance took %s", d)
	}
}

// waitForSSHAnyUser gives up as soon as abort closes, with errQEMUExited,
// unless the context ended first.
func TestWaitForSSHAnyUserStopsOnAbort(t *testing.T) {
	installEarlyExitFakes(t, "#!/bin/sh\nexit 0\n", "#!/bin/sh\necho 'Connection refused' >&2\nexit 255\n")
	abort := make(chan struct{})
	close(abort)
	base := sshTarget{PrivateKey: "/nonexistent", Port: 1}

	start := time.Now()
	_, err := waitForSSHAnyUser(context.Background(), base, []string{"ubuntu"}, 30*time.Second, abort)
	if !errors.Is(err, errQEMUExited) {
		t.Fatalf("err = %v, want errQEMUExited", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("abort took %s", d)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = waitForSSHAnyUser(ctx, base, []string{"ubuntu"}, 30*time.Second, abort)
	if err == nil || errors.Is(err, errQEMUExited) {
		t.Fatalf("cancelled context must report the context, got %v", err)
	}
}

// The qemu.log tail lands in InfraError, which the public API passes through
// (it strips vm_run_dir / qemu_command / serial_log only), so host paths must
// be replaced by placeholders, in given and symlink-resolved forms.
func TestExecuteProfileEarlyQEMUExitRedactsHostPaths(t *testing.T) {
	qemu := `#!/bin/sh
echo "qemu-system-x86_64: -drive file=$BPFCOMPAT_FAKE_OVERLAY,if=virtio: Could not open backing file '$BPFCOMPAT_FAKE_BASE': Permission denied" >&2
echo "qemu-system-x86_64: -serial file:$BPFCOMPAT_FAKE_SERIAL_RESOLVED: Permission denied" >&2
exit 1
`
	installEarlyExitFakes(t, qemu, "")
	p := earlyExitProfile(t)

	realDir := t.TempDir()
	runDir := filepath.Join(t.TempDir(), "run-link")
	if err := os.Symlink(realDir, runDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BPFCOMPAT_FAKE_OVERLAY", filepath.Join(runDir, "targets", p.ID, "overlay.qcow2"))
	t.Setenv("BPFCOMPAT_FAKE_SERIAL_RESOLVED", filepath.Join(realDir, "targets", p.ID, "serial.log"))
	t.Setenv("BPFCOMPAT_FAKE_BASE", p.Image.LocalPath)

	res := ExecuteProfile(context.Background(), ExecutionRequest{Profile: p, RunDir: runDir, Timeout: 10 * time.Second})
	t.Logf("infra=%q", res.InfraError)
	for _, want := range []string{
		"-drive file=<run-dir>/overlay.qcow2,if=virtio",
		"Could not open backing file '<base-image>'",
		"-serial file:<run-dir>/serial.log: Permission denied",
	} {
		if !strings.Contains(res.InfraError, want) {
			t.Fatalf("infra error %q does not contain %q", res.InfraError, want)
		}
	}
	for _, leaked := range []string{runDir, realDir, p.Image.LocalPath, filepath.Dir(p.Image.LocalPath)} {
		if strings.Contains(res.InfraError, leaked) {
			t.Fatalf("infra error leaks host path %q: %q", leaked, res.InfraError)
		}
	}
}

// The byte-bounded qemu.log tail must never split a UTF-8 sequence.
func TestQEMULogTailCutsOnUTF8Boundary(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "qemu.log")
	// 2*300 + 1 bytes: the last 512 bytes start inside a two-byte "é".
	if err := os.WriteFile(logPath, []byte(strings.Repeat("é", 300)+"a"), 0o600); err != nil {
		t.Fatal(err)
	}
	tail := qemuLogTail(logPath, newQEMULogRedactor(t.TempDir(), "", ""))
	if !utf8.ValidString(tail) || strings.ContainsRune(tail, utf8.RuneError) {
		t.Fatalf("tail is not clean UTF-8: %q", tail)
	}
	if tail != strings.Repeat("é", 255)+"a" {
		t.Fatalf("tail = %d bytes %q, want 255 whole runes", len(tail), tail)
	}
}
