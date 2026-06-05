package runtime

import (
	"errors"
	"strings"
	"testing"
)

func TestRunBPFToolProbePrivilegedRoot(t *testing.T) {
	originalRun := runCommandWithOutputFn
	originalUID := getEffectiveUIDFn
	originalLookPath := lookPathFn
	t.Cleanup(func() {
		runCommandWithOutputFn = originalRun
		getEffectiveUIDFn = originalUID
		lookPathFn = originalLookPath
	})

	lookPathFn = func(file string) (string, error) { return "/usr/sbin/bpftool", nil }
	getEffectiveUIDFn = func() int { return 0 }
	runCommandWithOutputFn = func(name string, args ...string) (string, error) {
		// Probe now resolves bpftool via lookPath and passes the absolute path
		// down to runCommandWithOutput so PATH lookup happens exactly once and
		// the elevated-sudo case can't fall back to a different binary.
		if name != "/usr/sbin/bpftool" {
			t.Fatalf("unexpected command: %s", name)
		}
		return "eBPF map_type ringbuf is available\n", nil
	}

	out, mode, restricted, warning, err := runBPFToolProbe(ProbeOptions{PreferPrivileged: true})
	if err != nil {
		t.Fatalf("runBPFToolProbe: %v", err)
	}
	if mode != "bpftool_privileged" {
		t.Fatalf("expected privileged mode, got %s", mode)
	}
	if restricted {
		t.Fatalf("expected unrestricted probe")
	}
	if warning != "" {
		t.Fatalf("expected empty warning, got %q", warning)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatalf("expected probe output")
	}
}

func TestRunBPFToolProbeSudoFallbackToUnprivileged(t *testing.T) {
	originalRun := runCommandWithOutputFn
	originalUID := getEffectiveUIDFn
	originalLookPath := lookPathFn
	t.Cleanup(func() {
		runCommandWithOutputFn = originalRun
		getEffectiveUIDFn = originalUID
		lookPathFn = originalLookPath
	})

	lookPathFn = func(file string) (string, error) { return "/usr/sbin/bpftool", nil }
	getEffectiveUIDFn = func() int { return 1000 }
	runCommandWithOutputFn = func(name string, args ...string) (string, error) {
		if name == "sudo" {
			return "", errors.New("sudo denied")
		}
		// runBPFToolUnprivileged now invokes the resolved absolute path,
		// so unprivileged probes arrive with name == "/usr/sbin/bpftool".
		if name == "/usr/sbin/bpftool" && len(args) >= 4 && args[3] == "unprivileged" {
			return "Scanning system...\nrestricted to privileged users (without recovery)\neBPF map_type ringbuf is not available\n", nil
		}
		return "", errors.New("unexpected command")
	}

	_, mode, restricted, warning, err := runBPFToolProbe(ProbeOptions{
		PreferPrivileged:   true,
		UseSudo:            true,
		SudoNonInteractive: true,
	})
	if err != nil {
		t.Fatalf("runBPFToolProbe: %v", err)
	}
	if mode != "bpftool_unprivileged" {
		t.Fatalf("expected unprivileged fallback mode, got %s", mode)
	}
	if !restricted {
		t.Fatalf("expected restricted=true for unprivileged probe output")
	}
	if strings.TrimSpace(warning) == "" {
		t.Fatalf("expected fallback warning")
	}
}

func TestRunBPFToolProbeBothFail(t *testing.T) {
	originalRun := runCommandWithOutputFn
	originalUID := getEffectiveUIDFn
	originalLookPath := lookPathFn
	t.Cleanup(func() {
		runCommandWithOutputFn = originalRun
		getEffectiveUIDFn = originalUID
		lookPathFn = originalLookPath
	})

	lookPathFn = func(file string) (string, error) { return "/usr/sbin/bpftool", nil }
	getEffectiveUIDFn = func() int { return 1000 }
	runCommandWithOutputFn = func(name string, args ...string) (string, error) {
		return "", errors.New("command failed")
	}

	_, _, _, _, err := runBPFToolProbe(ProbeOptions{
		PreferPrivileged:   true,
		UseSudo:            true,
		SudoNonInteractive: true,
	})
	if err == nil {
		t.Fatalf("expected error when privileged and unprivileged probes both fail")
	}
}
