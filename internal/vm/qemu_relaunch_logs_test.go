package vm

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The kernel-install path relaunches QEMU on the same run directory. The
// relaunch must append to serial.log and qemu.log, not truncate them, or the
// first boot and the installer output are lost from the evidence.
//
// The fake QEMU models QEMU's file semantics: "-serial file:P" and
// "-chardev file,...,path=P" without append=on truncate P; append=on appends.
func TestExecuteProfileKernelInstallRelaunchPreservesLogs(t *testing.T) {
	state := t.TempDir()
	t.Setenv("BPFCOMPAT_FAKE_STATE", state)
	qemu := `#!/bin/sh
s="$BPFCOMPAT_FAKE_STATE"
serial=""; mode=trunc; prev=""
for a; do
	case "$prev" in
	-serial) case "$a" in file:*) serial="${a#file:}"; mode=trunc ;; esac ;;
	-chardev)
		case "$a" in *,append=on*) mode=append ;; *) mode=trunc ;; esac
		serial="${a#*,path=}"; serial="${serial%%,append=on*}" ;;
	esac
	prev="$a"
done
[ -n "$serial" ] || { echo "fake-qemu: no serial file in argv" >&2; exit 2; }
if [ ! -e "$s/launched" ]; then
	: > "$s/launched"
	echo "fake-qemu launch 1 stderr" >&2
	if [ "$mode" = append ]; then printf 'Linux version FIRST-BOOT\n' >> "$serial"; else printf 'Linux version FIRST-BOOT\n' > "$serial"; fi
	: > "$s/running"
	i=0
	while [ ! -e "$s/reboot" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done
	printf 'installer: reboot requested\n' >> "$serial"
	rm -f "$s/running"
	exit 0
fi
echo "fake-qemu launch 2 stderr" >&2
if [ "$mode" = append ]; then printf 'Linux version SECOND-BOOT\n' >> "$serial"; else printf 'Linux version SECOND-BOOT\n' > "$serial"; fi
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

	res := ExecuteProfile(context.Background(), ExecutionRequest{Profile: p, RunDir: t.TempDir(), Timeout: 20 * time.Second})
	t.Logf("status=%q infra=%q", res.Status, res.InfraError)
	if res.Status != "infra_error" || !strings.Contains(res.InfraError, "after kernel-install reboot") {
		t.Fatalf("expected the relaunched fake QEMU to die after reboot, got status=%q infra=%q", res.Status, res.InfraError)
	}
	// The recorded command is the first launch, which keeps -serial file:.
	if !strings.Contains(res.QEMUCommand, " -serial file:") || strings.Contains(res.QEMUCommand, "-chardev") {
		t.Fatalf("recorded QEMU command changed for the first launch: %q", res.QEMUCommand)
	}

	serial, err := os.ReadFile(res.SerialLogPath)
	if err != nil {
		t.Fatal(err)
	}
	wantSerial := "Linux version FIRST-BOOT\ninstaller: reboot requested\nLinux version SECOND-BOOT\n"
	if string(serial) != wantSerial {
		t.Errorf("serial.log = %q, want %q", serial, wantSerial)
	}
	qlog, err := os.ReadFile(filepath.Join(filepath.Dir(res.SerialLogPath), "qemu.log"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(qlog)
	first := strings.Index(text, "fake-qemu launch 1 stderr")
	sep := strings.Index(text, "=== relaunch after kernel install ===")
	second := strings.Index(text, "fake-qemu launch 2 stderr")
	if first < 0 || sep < 0 || second < 0 || first >= sep || sep >= second {
		t.Errorf("qemu.log must hold launch 1, the relaunch separator, then launch 2 in order; got %q", text)
	}
	// The early-exit tail quotes only the relaunched QEMU's own output, as
	// it did when qemu.log was truncated on relaunch.
	if !strings.HasSuffix(res.InfraError, "qemu exited before SSH was ready (exit status 1): fake-qemu launch 2 stderr") {
		t.Fatalf("infra error must quote only the relaunch's qemu.log output: %q", res.InfraError)
	}
}

// The first launch argv is unchanged: -serial file:<path> verbatim (even with
// a "," in the path, as before), no -chardev, identical to buildQEMUArgs.
func TestBuildQEMUArgsFirstLaunchSerialUnchanged(t *testing.T) {
	profile := Profile{Arch: "x86_64"}
	got := buildQEMUArgsForLaunch(profile, "/tmp/overlay.qcow2", "/tmp/a,b/serial.log", 2222, seedDeliveryNoCloudNet, "http://127.0.0.1:8080/", "", "", false)
	if !reflect.DeepEqual(got, buildQEMUArgs(profile, "/tmp/overlay.qcow2", "/tmp/a,b/serial.log", 2222, seedDeliveryNoCloudNet, "http://127.0.0.1:8080/", "", "")) {
		t.Fatalf("first-launch argv differs from buildQEMUArgs: %q", got)
	}
	if !containsArgSequence(got, []string{"-serial", "file:/tmp/a,b/serial.log"}) {
		t.Fatalf("first launch must keep -serial file:<path> verbatim: %q", got)
	}
	for _, a := range got {
		if a == "-chardev" || strings.Contains(a, "append=on") {
			t.Fatalf("first launch must not use an appending chardev: %q", got)
		}
	}
}

// The relaunch appends to serial.log through a file chardev; QEMU's option
// parser splits on ",", so a "," in the path is escaped as ",,".
func TestBuildQEMUArgsRelaunchAppendsSerial(t *testing.T) {
	profile := Profile{Arch: "x86_64"}
	for _, tc := range []struct{ path, want string }{
		{"/tmp/run/serial.log", "file,id=bpfserial0,path=/tmp/run/serial.log,append=on"},
		{"/tmp/a,b/c,,d/serial.log", "file,id=bpfserial0,path=/tmp/a,,b/c,,,,d/serial.log,append=on"},
	} {
		got := buildQEMUArgsForLaunch(profile, "/tmp/overlay.qcow2", tc.path, 2222, seedDeliveryNoCloudNet, "http://127.0.0.1:8080/", "", "", true)
		if !containsArgSequence(got, []string{"-chardev", tc.want, "-serial", "chardev:bpfserial0"}) {
			t.Fatalf("relaunch argv for %q = %q, want -chardev %q -serial chardev:bpfserial0", tc.path, got, tc.want)
		}
		for _, a := range got {
			if strings.HasPrefix(a, "file:") {
				t.Fatalf("relaunch must not use the truncating -serial file: form: %q", got)
			}
		}
		// Only the serial wiring differs from the first launch.
		first := buildQEMUArgsForLaunch(profile, "/tmp/overlay.qcow2", tc.path, 2222, seedDeliveryNoCloudNet, "http://127.0.0.1:8080/", "", "", false)
		if len(got) != len(first)+2 {
			t.Fatalf("relaunch argv length %d, first launch %d: %q vs %q", len(got), len(first), got, first)
		}
	}
}

// With the relaunch separator in qemu.log the tail is still redacted and
// covers only the relaunched QEMU.
func TestQEMULogTailAfterRelaunchSeparatorIsRedacted(t *testing.T) {
	runDir := t.TempDir()
	logPath := filepath.Join(runDir, "qemu.log")
	body := "first launch: " + runDir + "/overlay.qcow2 ok\n\n" + qemuRelaunchSeparator + "\n" +
		"qemu-system-x86_64: -chardev file,id=bpfserial0,path=" + runDir + "/serial.log,append=on: Permission denied\n"
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	tail := qemuLogTail(logPath, newQEMULogRedactor(runDir, "", ""))
	want := "qemu-system-x86_64: -chardev file,id=bpfserial0,path=<run-dir>/serial.log,append=on: Permission denied"
	if tail != want {
		t.Fatalf("tail = %q, want %q", tail, want)
	}
}

func containsArgSequence(args, seq []string) bool {
	for i := 0; i+len(seq) <= len(args); i++ {
		if reflect.DeepEqual(args[i:i+len(seq)], seq) {
			return true
		}
	}
	return false
}
