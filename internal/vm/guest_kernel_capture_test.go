package vm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeSSH puts fake ssh/scp binaries in front of PATH. The fake ssh
// reads the in-guest script from stdin (sshScriptCommand sends it there):
// `uname -r` answers according to unameMode ("ok", "empty", "fail"), and the
// user-command wrapper touches markerPath so a test can tell whether the user
// command was started. The fake scp writes "0" for the exit-code file and
// leaves other downloads empty.
func installFakeSSH(t *testing.T, unameMode, markerPath string) {
	t.Helper()
	dir := t.TempDir()
	ssh := `#!/bin/sh
script=$(cat)
case "$script" in
"uname -r")
  case "` + unameMode + `" in
  ok) echo 5.15.0-152-generic ;;
  empty) echo "" ;;
  *) echo "uname: boom" >&2; exit 1 ;;
  esac ;;
"uname -m") echo x86_64 ;;
*"bash -lc"*) : > '` + markerPath + `' ;;
esac
exit 0
`
	scp := `#!/bin/sh
for a; do last="$a"; done
case "$last" in
*command-exit-code) echo 0 > "$last" ;;
*) : > "$last" ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(ssh), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scp"), []byte(scp), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

func runFakeGuestCommand(t *testing.T, unameMode string) (ExecutionResult, bool) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "user-command-ran")
	installFakeSSH(t, unameMode, marker)
	result := ExecutionResult{Status: "infra_error"}
	target := sshTarget{User: "ubuntu", PrivateKey: "/dev/null", Port: 2222}
	req := ExecutionRequest{Command: "true"}
	runGuestCommand(context.Background(), req, target, t.TempDir(), "/tmp/bpfcompat", "", &result)
	_, err := os.Stat(marker)
	return result, err == nil
}

// The guest kernel release is the identity of a command-mode result. If it
// cannot be recorded, the run is an infrastructure error and the user's
// command must not be started at all.
func TestRunGuestCommandRequiresGuestKernelRelease(t *testing.T) {
	for _, mode := range []string{"fail", "empty"} {
		t.Run(mode, func(t *testing.T) {
			result, ran := runFakeGuestCommand(t, mode)
			if result.Status == "pass" {
				t.Fatalf("status=pass with uname -r %s; want infra error", mode)
			}
			if !strings.HasPrefix(result.InfraError, "record guest kernel release: ") {
				t.Fatalf("infra_error=%q; want prefix %q", result.InfraError, "record guest kernel release: ")
			}
			if result.HostRelease != "" {
				t.Fatalf("host_release=%q; want empty", result.HostRelease)
			}
			if ran {
				t.Fatal("user command ran although the guest kernel release was not recorded")
			}
		})
	}
}

// Control: a normal command run records the kernel and runs the command.
func TestRunGuestCommandRecordsKernelAndRuns(t *testing.T) {
	result, ran := runFakeGuestCommand(t, "ok")
	if result.Status != "pass" || result.InfraError != "" {
		t.Fatalf("status=%q infra_error=%q; want pass", result.Status, result.InfraError)
	}
	if result.HostRelease != "5.15.0-152-generic" || result.HostMachine != "x86_64" {
		t.Fatalf("host=%q/%q; want 5.15.0-152-generic/x86_64", result.HostRelease, result.HostMachine)
	}
	if !ran {
		t.Fatal("user command was not run")
	}
	if result.CommandExitCode != 0 {
		t.Fatalf("exit=%d; want 0", result.CommandExitCode)
	}
}
