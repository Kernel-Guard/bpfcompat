package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/runner"
)

func TestProbeKVMRejectsUnusableDevices(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "kvm")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ dev, want string }{
		"missing":       {filepath.Join(t.TempDir(), "nope"), "does not exist"},
		"regular file":  {regular, "not a character device"},
		"wrong chardev": {"/dev/null", "KVM_GET_API_VERSION"}, // opens fine, but is not KVM
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			st := probeKVM(tc.dev)
			if st.Usable || !strings.Contains(st.Detail, tc.want) {
				t.Fatalf("probeKVM(%s) = %+v, want unusable with %q", tc.dev, st, tc.want)
			}
		})
	}
}

func TestProbeKVMRealDevice(t *testing.T) {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no usable /dev/kvm on this host: %v", err)
	}
	_ = f.Close()
	if st := probeKVM("/dev/kvm"); !st.Usable {
		t.Fatalf("openable /dev/kvm reported unusable: %+v", st)
	}
}

func TestWarnIfKVMUnusable(t *testing.T) {
	orig := kvmDevicePath
	t.Cleanup(func() { kvmDevicePath = orig })
	kvmDevicePath = filepath.Join(t.TempDir(), "kvm")

	var buf bytes.Buffer
	warnIfKVMUnusable(runner.Config{Runner: runner.RunnerVM}, &buf)
	if got := buf.String(); !strings.Contains(got, "warning: KVM is not usable") || !strings.Contains(got, "TCG") || !strings.Contains(got, "bpfcompat doctor") {
		t.Fatalf("missing TCG warning, got %q", got)
	}

	buf.Reset()
	warnIfKVMUnusable(runner.Config{Runner: runner.RunnerFirecracker}, &buf)
	if buf.Len() != 0 {
		t.Fatalf("non-QEMU runner should not warn, got %q", buf.String())
	}
}

func TestDoctorFlagsUnusableKVM(t *testing.T) {
	orig := kvmDevicePath
	t.Cleanup(func() { kvmDevicePath = orig })
	kvmDevicePath = filepath.Join(t.TempDir(), "kvm")
	t.Chdir(t.TempDir())

	checks := doctorChecks(nil, "none", false)
	var kvm *doctorCheck
	for i := range checks {
		if checks[i].Name == "kvm" {
			kvm = &checks[i]
		}
	}
	if kvm == nil || kvm.Level != doctorFail || !strings.Contains(kvm.Detail, "TCG") || !strings.Contains(kvm.Detail, "fix:") {
		t.Fatalf("kvm check = %+v", kvm)
	}
	var out bytes.Buffer
	if code := printDoctor(&out, checks); code != runner.ExitToolError {
		t.Fatalf("printDoctor exit=%d with a failing check", code)
	}
	out.Reset()
	if code := printDoctor(&out, []doctorCheck{{doctorOK, "x", "y"}, {doctorWarn, "z", "w"}}); code != 0 || !strings.Contains(out.String(), "ready") {
		t.Fatalf("warnings alone must not fail: exit=%d out=%q", code, out.String())
	}
}
