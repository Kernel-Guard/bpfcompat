//go:build !linux

package vm

import "os/exec"

// killWithParent is a no-op where the parent-death signal does not exist.
func killWithParent(*exec.Cmd) {}
