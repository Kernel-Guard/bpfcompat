package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAarch64PflashArgs(t *testing.T) {
	args := aarch64PflashArgs("/fw/CODE.fd", "/run/VARS.fd")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "if=pflash,format=raw,unit=0,readonly=on,file=/fw/CODE.fd") {
		t.Errorf("missing read-only CODE pflash unit 0: %s", joined)
	}
	if !strings.Contains(joined, "if=pflash,format=raw,unit=1,file=/run/VARS.fd") {
		t.Errorf("missing writable VARS pflash unit 1: %s", joined)
	}
}

func TestAarch64FirmwareArgsStagesWritableVars(t *testing.T) {
	dir := t.TempDir()
	code := filepath.Join(dir, "CODE.fd")
	vars := filepath.Join(dir, "VARS.fd")
	if err := os.WriteFile(code, []byte("code"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vars, []byte("vars-template"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BPFCOMPAT_AARCH64_UEFI_CODE", code)
	t.Setenv("BPFCOMPAT_AARCH64_UEFI_VARS", vars)

	runDir := t.TempDir()
	args, err := aarch64FirmwareArgs(runDir)
	if err != nil {
		t.Fatalf("aarch64FirmwareArgs: %v", err)
	}
	// A writable per-VM copy must exist under runDir (not the shared template).
	copyPath := filepath.Join(runDir, "AAVMF_VARS.fd")
	if _, err := os.Stat(copyPath); err != nil {
		t.Fatalf("expected staged vars copy at %s: %v", copyPath, err)
	}
	if !strings.Contains(strings.Join(args, " "), copyPath) {
		t.Errorf("pflash args should reference the staged vars copy, got %v", args)
	}
}

func TestAarch64FirmwareArgsMissing(t *testing.T) {
	t.Setenv("BPFCOMPAT_AARCH64_UEFI_CODE", "/nonexistent/CODE.fd")
	t.Setenv("BPFCOMPAT_AARCH64_UEFI_VARS", "/nonexistent/VARS.fd")
	// With overrides pointing nowhere and (in CI) no system firmware, this errors
	// clearly rather than silently producing an unbootable VM.
	if _, err := aarch64FirmwareArgs(t.TempDir()); err == nil {
		t.Skip("system firmware present; missing-firmware path not exercised here")
	}
}
