//go:build linux

package vm

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// installFakeQEMU puts a stand-in qemu-system-x86_64 (a plain `sleep`, no
// VM) first on PATH.
func installFakeQEMU(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nexec sleep 120\n"
	if err := os.WriteFile(filepath.Join(dir, "qemu-system-x86_64"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake qemu: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func startFakeQEMU(t *testing.T) *exec.Cmd {
	t.Helper()
	dir := t.TempDir()
	cmd, _, err := startQEMU(context.Background(), Profile{ID: "fake", Arch: "x86_64"},
		filepath.Join(dir, "overlay.qcow2"), filepath.Join(dir, "serial.log"), filepath.Join(dir, "qemu.log"),
		2222, "", "", "", "")
	if err != nil {
		t.Fatalf("startQEMU: %v", err)
	}
	return cmd
}

// A4-1: QEMU must be SIGKILLed by the kernel if bpfcompat dies, so a
// crashed or force-killed server never leaves orphaned guests behind.
func TestStartQEMUSetsParentDeathSignal(t *testing.T) {
	installFakeQEMU(t)
	cmd := startFakeQEMU(t)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("qemu SysProcAttr = %+v, want Pdeathsig=SIGKILL", cmd.SysProcAttr)
	}
}

const envOrphanChildPIDFile = "BPFCOMPAT_TEST_QEMU_ORPHAN_PIDFILE"

// TestQEMUOrphanHelper is the intermediate process for
// TestQEMUDiesWithParent: it starts the fake QEMU, records its PID and
// blocks until killed.
func TestQEMUOrphanHelper(t *testing.T) {
	pidFile := os.Getenv(envOrphanChildPIDFile)
	if pidFile == "" {
		t.Skip("helper process for TestQEMUDiesWithParent")
	}
	cmd := startFakeQEMU(t)
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	time.Sleep(time.Minute)
}

func processGone(pid int) bool {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	// Field 3 of /proc/<pid>/stat is the state; a zombie is already dead.
	fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}

func TestQEMUDiesWithParent(t *testing.T) {
	installFakeQEMU(t)
	pidFile := filepath.Join(t.TempDir(), "qemu.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	helper := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQEMUOrphanHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), envOrphanChildPIDFile+"="+pidFile)
	if err := helper.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	var pid int
	deadline := time.Now().Add(10 * time.Second)
	for pid == 0 {
		if raw, err := os.ReadFile(pidFile); err == nil && len(raw) > 0 {
			pid, _ = strconv.Atoi(string(raw))
		}
		if time.Now().After(deadline) {
			_ = helper.Process.Kill()
			_ = helper.Wait()
			t.Fatal("helper never started the fake qemu")
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer func() { _ = syscall.Kill(pid, syscall.SIGKILL) }()

	// Simulate bpfcompat dying hard (SIGKILL: no deferred cleanup runs).
	if err := helper.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	var exitErr *exec.ExitError
	if err := helper.Wait(); err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("wait helper: %v", err)
	}

	deadline = time.Now().Add(5 * time.Second)
	for !processGone(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("fake qemu (pid %d) outlived its killed parent: orphaned", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
