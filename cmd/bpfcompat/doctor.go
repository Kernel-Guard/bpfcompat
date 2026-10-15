package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/kernel-guard/bpfcompat/internal/matrix"
	"github.com/kernel-guard/bpfcompat/internal/profilecatalog"
	"github.com/kernel-guard/bpfcompat/internal/runner"
)

// kvmStatus is the result of probeKVM (kvm_linux.go / kvm_other.go).
type kvmStatus struct {
	Usable bool
	Detail string
	Hint   string
}

// kvmDevicePath is the device probed by doctor and the pre-run KVM warning.
// Tests point it elsewhere.
var kvmDevicePath = "/dev/kvm"

type doctorLevel string

const (
	doctorOK   doctorLevel = "ok"
	doctorWarn doctorLevel = "warn"
	doctorFail doctorLevel = "FAIL"
)

type doctorCheck struct {
	Level  doctorLevel
	Name   string
	Detail string
}

// hostToolchain lists the host executables the VM runner shells out to, with
// the package that provides each on Debian/Ubuntu and Fedora.
func hostToolchain() []struct {
	Bin, Pkg string
	Required bool
} {
	qemu, qemuPkg := "qemu-system-x86_64", "qemu-system-x86 (Debian/Ubuntu) / qemu-system-x86-core (Fedora)"
	if runtime.GOARCH == "arm64" {
		qemu, qemuPkg = "qemu-system-aarch64", "qemu-system-arm (Debian/Ubuntu) / qemu-system-aarch64-core (Fedora)"
	}
	return []struct {
		Bin, Pkg string
		Required bool
	}{
		{qemu, qemuPkg, true},
		{"qemu-img", "qemu-utils (Debian/Ubuntu) / qemu-img (Fedora)", true},
		{"ssh", "openssh-client (Debian/Ubuntu) / openssh-clients (Fedora)", true},
		{"scp", "openssh-client (Debian/Ubuntu) / openssh-clients (Fedora)", true},
		{"ssh-keygen", "openssh-client (Debian/Ubuntu) / openssh-clients (Fedora)", true},
		{"cloud-localds", "cloud-image-utils (Debian/Ubuntu) / cloud-utils (Fedora); needed by RHEL-family, Amazon, Oracle and SUSE profiles", false},
	}
}

// runDoctor checks that this host can run VM-backed `bpfcompat test`: host
// tools, real KVM usability, the guest validator, and where each profile and
// its image would come from. It changes nothing on the host.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	matrixPath := fs.String("matrix", "", "Check the profiles of this matrix instead of the built-in --quick set")
	commandMode := fs.Bool("command-mode", false, "Skip the validator check (command-mode runs ship their own loader)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat doctor [--matrix <file>] [--command-mode]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "doctor: unexpected positional arguments: %v\n", fs.Args())
		return runner.ExitToolError
	}

	ids := matrix.QuickProfileIDs
	setName := "--quick set"
	if *matrixPath != "" {
		m, err := matrix.Load(filepath.Clean(*matrixPath))
		if err != nil {
			fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
			return runner.ExitToolError
		}
		ids = m.ProfileIDs()
		setName = *matrixPath
	}

	checks := doctorChecks(ids, setName, !*commandMode)
	return printDoctor(os.Stdout, checks)
}

func doctorChecks(profileIDs []string, setName string, wantValidator bool) []doctorCheck {
	var checks []doctorCheck
	for _, tool := range hostToolchain() {
		if p, err := exec.LookPath(tool.Bin); err == nil {
			checks = append(checks, doctorCheck{doctorOK, tool.Bin, p})
			continue
		}
		level := doctorFail
		if !tool.Required {
			level = doctorWarn
		}
		checks = append(checks, doctorCheck{level, tool.Bin, "not found on PATH; install " + tool.Pkg})
	}

	if st := probeKVM(kvmDevicePath); st.Usable {
		checks = append(checks, doctorCheck{doctorOK, "kvm", st.Detail})
	} else {
		detail := st.Detail + "; VM runs would fall back to slow TCG software emulation"
		if st.Hint != "" {
			detail += "; fix: " + st.Hint
		}
		checks = append(checks, doctorCheck{doctorFail, "kvm", detail})
	}

	if wantValidator {
		switch path, dynamic, err := runner.LocateValidatorBinary(); {
		case err != nil:
			checks = append(checks, doctorCheck{doctorFail, "validator", err.Error()})
		case dynamic:
			checks = append(checks, doctorCheck{doctorFail, "validator", path + " is dynamically linked; VM-backed runs need the static build (`make validator-static` or the release's bpfcompat-validator-static asset)"})
		default:
			checks = append(checks, doctorCheck{doctorOK, "validator", path + " (static)"})
		}
	}

	usesCache := false
	for _, id := range profileIDs {
		loc, err := profilecatalog.Locate(id)
		if err != nil {
			checks = append(checks, doctorCheck{doctorFail, "profile " + id, err.Error()})
			continue
		}
		where := loc.Path
		if loc.Source == profilecatalog.SourceBuiltin {
			where = "built-in catalog"
			usesCache = true
		}
		detail := fmt.Sprintf("%s (%s, from %s)", where, loc.Source, setName)
		if img, err := profilecatalog.ImagePath(loc); err == nil && img != "" {
			if _, statErr := os.Stat(img); statErr == nil {
				detail += "; image cached at " + img
			} else {
				detail += "; image not cached yet, the first run downloads it (hundreds of MB) to " + img
			}
		}
		if pin, err := profilecatalog.ImagePin(loc); err == nil {
			if pin != "" {
				detail += "; image digest pinned (sha256 " + pin + "), verified on every run"
			} else {
				detail += "; image digest not pinned (the observed sha256 is recorded as provenance, not verified)"
			}
		}
		checks = append(checks, doctorCheck{doctorOK, "profile " + id, detail})
	}

	if usesCache {
		root, err := profilecatalog.CacheRoot()
		switch {
		case err != nil:
			checks = append(checks, doctorCheck{doctorFail, "image cache", err.Error()})
		case !writableOrCreatable(root):
			checks = append(checks, doctorCheck{doctorFail, "image cache", root + " is not writable; set " + profilecatalog.EnvCacheDir})
		default:
			checks = append(checks, doctorCheck{doctorOK, "image cache", root + " (set " + profilecatalog.EnvCacheDir + " to move it)"})
		}
	}
	return checks
}

// writableOrCreatable reports whether dir, or the nearest existing ancestor it
// would be created under, is writable by this process.
func writableOrCreatable(dir string) bool {
	for {
		if _, err := os.Stat(dir); err == nil {
			return syscall.Access(dir, 2 /* W_OK */) == nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

func printDoctor(w io.Writer, checks []doctorCheck) int {
	failures := 0
	for _, c := range checks {
		if c.Level == doctorFail {
			failures++
		}
		fmt.Fprintf(w, "[%-4s] %-28s %s\n", c.Level, c.Name, c.Detail)
	}
	if failures > 0 {
		fmt.Fprintf(w, "\n%d problem(s) found; VM-backed `bpfcompat test` is not ready on this host.\n", failures)
		return runner.ExitToolError
	}
	fmt.Fprintln(w, "\nThis host is ready for VM-backed `bpfcompat test`.")
	return 0
}

// warnIfKVMUnusable makes the TCG fallback visible: when KVM cannot be used,
// QEMU boots same-architecture guests under software emulation, which is
// much slower and can run past --timeout. It only warns; the run proceeds as
// before.
func warnIfKVMUnusable(cfg runner.Config, w io.Writer) {
	if r := strings.TrimSpace(cfg.Runner); r != "" && r != runner.RunnerVM {
		return
	}
	st := probeKVM(kvmDevicePath)
	if st.Usable {
		return
	}
	msg := fmt.Sprintf("warning: KVM is not usable (%s). Guests will boot under QEMU TCG software emulation, which is much slower and may exceed --timeout.", st.Detail)
	if st.Hint != "" {
		msg += " Fix: " + st.Hint + "."
	}
	fmt.Fprintln(w, msg+" Run `bpfcompat doctor` for a full host check.")
}
