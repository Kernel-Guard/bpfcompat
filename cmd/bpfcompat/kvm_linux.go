//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

const (
	kvmGetAPIVersion = 0xAE00 // _IO(KVMIO, 0x00)
	kvmCreateVM      = 0xAE01 // _IO(KVMIO, 0x01)
	kvmAPIVersion    = 12     // stable since Linux 2.6.22
)

// probeKVM checks that KVM is actually usable, not merely present: the device
// must open read-write, answer KVM_GET_API_VERSION with the stable API, and
// let this process create a VM. Each failure carries the fix when one is known.
func probeKVM(dev string) kvmStatus {
	info, err := os.Stat(dev)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return kvmStatus{Detail: dev + " does not exist",
			Hint: "enable hardware virtualization (VT-x/AMD-V, or nested virtualization on a cloud VM) and load the kvm_intel or kvm_amd module"}
	case err != nil:
		return kvmStatus{Detail: fmt.Sprintf("stat %s: %v", dev, err)}
	case info.Mode()&os.ModeCharDevice == 0:
		return kvmStatus{Detail: dev + " is not a character device"}
	}

	f, err := os.OpenFile(dev, os.O_RDWR, 0) // #nosec G304 -- fixed device path (overridable only in tests).
	if err != nil {
		st := kvmStatus{Detail: fmt.Sprintf("cannot open %s read-write: %v", dev, err)}
		if errors.Is(err, os.ErrPermission) {
			st.Hint = `add your user to the kvm group (sudo usermod -aG kvm "$USER", then log out and back in) or grant access with a udev rule`
		}
		return st
	}
	defer f.Close()

	version, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), kvmGetAPIVersion, 0)
	if errno != 0 {
		return kvmStatus{Detail: fmt.Sprintf("KVM_GET_API_VERSION on %s failed: %v", dev, errno)}
	}
	if version != kvmAPIVersion {
		return kvmStatus{Detail: fmt.Sprintf("unexpected KVM API version %d on %s (want %d)", version, dev, kvmAPIVersion)}
	}
	vmfd, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), kvmCreateVM, 0)
	if errno != 0 {
		return kvmStatus{Detail: fmt.Sprintf("KVM_CREATE_VM on %s failed: %v", dev, errno),
			Hint: "another hypervisor may hold the virtualization extensions, or the host is out of resources"}
	}
	_ = syscall.Close(int(vmfd))
	return kvmStatus{Usable: true, Detail: fmt.Sprintf("%s usable (KVM API %d, VM creation ok)", dev, version)}
}
