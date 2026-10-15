//go:build linux

package vm

import (
	"os/exec"
	"syscall"
)

// killWithParent asks the kernel to SIGKILL cmd's process when bpfcompat
// dies, so a crashed or force-killed server cannot orphan a guest VM.
//
// Pdeathsig fires when the OS thread that forked the child exits; Go only
// retires threads whose goroutine called runtime.LockOSThread and exited
// locked, which bpfcompat never does on these spawn paths.
func killWithParent(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}
