package vm

import (
	"os"
	"path/filepath"
	"testing"
)

func setKVMDevicePath(t *testing.T, path string) {
	t.Helper()
	orig := kvmDevicePath
	t.Cleanup(func() { kvmDevicePath = orig })
	kvmDevicePath = path
}

func TestKVMAvailableRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kvm")
	if err := os.WriteFile(path, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	setKVMDevicePath(t, path)
	if kvmAvailable() {
		t.Fatalf("kvmAvailable() = true for regular file %s", path)
	}
}

func TestKVMAvailableRejectsMissingDevice(t *testing.T) {
	setKVMDevicePath(t, filepath.Join(t.TempDir(), "absent"))
	if kvmAvailable() {
		t.Fatal("kvmAvailable() = true for a missing device")
	}
}

// A character device that exists but this process cannot open read-write
// (e.g. /dev/kvm without kvm group membership) must degrade to TCG rather
// than make QEMU fail at -enable-kvm. /dev/mem stands in for such a device.
func TestKVMAvailableRejectsUnopenableCharDevice(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: every device node is openable")
	}
	dev := ""
	for _, candidate := range []string{"/dev/mem", "/dev/port", "/dev/kmem"} {
		info, err := os.Stat(candidate)
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			continue
		}
		if f, err := os.OpenFile(candidate, os.O_RDWR, 0); err == nil {
			_ = f.Close()
			continue
		}
		dev = candidate
		break
	}
	if dev == "" {
		t.Skip("no unopenable character device available on this host")
	}
	setKVMDevicePath(t, dev)
	if kvmAvailable() {
		t.Fatalf("kvmAvailable() = true for %s, which this process cannot open read-write", dev)
	}
}

// Keep the existing behaviour on hosts with a usable /dev/kvm.
func TestKVMAvailableAcceptsOpenableHostKVM(t *testing.T) {
	info, err := os.Stat("/dev/kvm")
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		t.Skip("no /dev/kvm character device on this host")
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("/dev/kvm not openable here: %v", err)
	}
	_ = f.Close()
	setKVMDevicePath(t, "/dev/kvm")
	if !kvmAvailable() {
		t.Fatal("kvmAvailable() = false although /dev/kvm is an openable character device")
	}
}
