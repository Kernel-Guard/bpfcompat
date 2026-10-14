package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SECURITY: API source uploads are compiled with clang on the API host. Any
// file clang can open (.incbin, #include, __has_include) can be embedded in
// the compiled object, and bytes of that object can return to the caller via
// verifier notes in the validation report. Authentication does not make that
// safe, so clang runs inside a bubblewrap sandbox that only sees the system
// toolchain (/usr and the /lib* links), the request directory, a fresh /tmp
// and a minimal /dev. When no working sandbox exists, source compilation is
// refused (fail closed) unless the operator explicitly opts out.

// envUnsandboxedSourceCompile is the operator opt-out that lets source
// uploads compile on the bare host when no sandbox backend works.
const envUnsandboxedSourceCompile = "BPFCOMPAT_API_UNSANDBOXED_SOURCE_COMPILE"

// errSourceCompileSandboxUnavailable is returned (HTTP 503) when source
// compilation needs the sandbox and none is usable on this server.
var errSourceCompileSandboxUnavailable = errors.New("source compilation is unavailable on this server: no working compiler sandbox; upload a prebuilt .bpf.o artifact")

const (
	// sourceCompileSandboxWorkDir is where the request directory appears
	// inside the sandbox (read-write; holds only the uploaded source).
	sourceCompileSandboxWorkDir = "/work"
	// Resource limits applied inside the sandbox before clang starts.
	sourceCompileAddressSpaceLimitKiB = 2 << 20 // 2 GiB of virtual memory
	sourceCompileFileSizeLimitBlocks  = 131072  // 64 MiB per file (512-byte ulimit blocks)
	sourceCompileSandboxProbeTimeout  = 15 * time.Second
	sourceCompileSandboxKillGrace     = 2 * time.Second
)

// sourceCompileBwrapBinary names the bubblewrap executable. Tests point it at
// a missing path to simulate a host without a usable sandbox.
var sourceCompileBwrapBinary = "bwrap"

// sourceCompileSandboxLimitScript runs as the sandboxed /bin/sh: it applies
// CPU, address-space, file-size and core-dump limits, then execs the command
// passed as positional arguments ($1 = CPU seconds). Only dash/POSIX ulimit
// flags are used; each limit is a separate call so dash accepts it.
const sourceCompileSandboxLimitScript = `cpu=$1; shift; ulimit -t "$cpu" && ulimit -v ` +
	"%d" + ` && ulimit -f ` + "%d" + ` && ulimit -c 0 && exec "$@"`

type sourceCompileSandboxState struct {
	mu     sync.Mutex
	probed bool
	bwrap  string
	clang  string
	err    error
}

var sourceCompileSandbox sourceCompileSandboxState

// resetSourceCompileSandboxProbe forgets the cached probe result (tests).
func resetSourceCompileSandboxProbe() {
	sourceCompileSandbox.mu.Lock()
	defer sourceCompileSandbox.mu.Unlock()
	sourceCompileSandbox.probed = false
	sourceCompileSandbox.bwrap, sourceCompileSandbox.clang, sourceCompileSandbox.err = "", "", nil
}

func unsandboxedSourceCompileAllowed() bool {
	return parseBoolEnv(envUnsandboxedSourceCompile, false)
}

// resolveSourceCompileSandbox probes once per process whether bubblewrap can
// run clang in the sandbox and caches the answer (restart the server after
// fixing the host). It returns the bwrap and clang paths to use.
func resolveSourceCompileSandbox(ctx context.Context, logger *slog.Logger) (string, string, error) {
	s := &sourceCompileSandbox
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.probed {
		return s.bwrap, s.clang, s.err
	}
	s.probed = true
	s.bwrap, s.clang, s.err = probeSourceCompileSandbox(ctx)
	if s.err != nil {
		logger.Error("source compile sandbox unavailable; source uploads are refused (set "+envUnsandboxedSourceCompile+"=true to compile on the bare host)",
			slog.String("error", s.err.Error()))
	} else {
		logger.Info("source compile sandbox ready", slog.String("bwrap", s.bwrap), slog.String("clang", s.clang))
	}
	return s.bwrap, s.clang, s.err
}

func probeSourceCompileSandbox(parent context.Context) (string, string, error) {
	bwrap, err := exec.LookPath(sourceCompileBwrapBinary)
	if err != nil {
		return "", "", fmt.Errorf("bubblewrap not found: %w", err)
	}
	clang, err := exec.LookPath("clang")
	if err != nil {
		return "", "", fmt.Errorf("clang not found: %w", err)
	}
	if clang, err = filepath.Abs(clang); err != nil {
		return "", "", err
	}
	// /usr/bin/clang is often an update-alternatives link through
	// /etc/alternatives, which is not mounted in the sandbox. Run the real
	// binary instead so such hosts do not fail closed for no reason.
	if resolved, rerr := filepath.EvalSymlinks(clang); rerr == nil {
		clang = resolved
	}
	workDir, err := os.MkdirTemp("", "bpfcompat-sandbox-probe-")
	if err != nil {
		return "", "", fmt.Errorf("create probe dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	// The cached result must not depend on the triggering request being
	// cancelled, so only its values (not its cancellation) carry over.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), sourceCompileSandboxProbeTimeout)
	defer cancel()
	out, err := runSourceCompileSandboxed(ctx, bwrap, workDir, sourceCompileSandboxProbeTimeout, []string{clang, "--version"})
	if err != nil {
		return "", "", fmt.Errorf("bwrap could not run clang (%w): %s", err, truncateForLog(strings.TrimSpace(string(out)), 1024))
	}
	return bwrap, clang, nil
}

// sourceCompileSandboxArgs builds the bwrap argv (without the bwrap binary
// itself) that runs command with workDir mounted at /work.
func sourceCompileSandboxArgs(workDir string, cpuLimit time.Duration, command []string) []string {
	args := []string{
		"--unshare-all", // user (if possible), ipc, pid, net, uts, cgroup
		"--die-with-parent",
		"--new-session",
		"--cap-drop", "ALL",
		"--clearenv",
		"--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "LANG", "C",
		"--setenv", "LC_ALL", "C",
	}
	var includeDirs []string
	for _, name := range []string{"CPATH", "C_INCLUDE_PATH"} {
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		args = append(args, "--setenv", name, value)
		includeDirs = append(includeDirs, filepath.SplitList(value)...)
	}

	args = append(args, "--ro-bind", "/usr", "/usr")
	for _, name := range []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"} {
		host := "/" + name
		info, err := os.Lstat(host)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Readlink(host); err == nil {
				args = append(args, "--symlink", target, host)
			}
			continue
		}
		if info.IsDir() {
			args = append(args, "--ro-bind", host, host)
		}
	}
	args = append(args,
		// Loader cache only (no secrets); lets clang find its shared
		// libraries on distros that rely on ld.so.conf.d entries.
		"--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
	)
	// Operator-configured header search paths stay usable at the same
	// path. They are exposed read-only to every compile.
	for _, dir := range includeDirs {
		dir = filepath.Clean(dir)
		if !filepath.IsAbs(dir) || dir == "/" || dir == "/usr" || strings.HasPrefix(dir, "/usr/") {
			continue
		}
		args = append(args, "--ro-bind-try", dir, dir)
	}
	args = append(args,
		"--bind", workDir, sourceCompileSandboxWorkDir,
		"--chdir", sourceCompileSandboxWorkDir,
		"--",
		"/bin/sh", "-c",
		fmt.Sprintf(sourceCompileSandboxLimitScript, sourceCompileAddressSpaceLimitKiB, sourceCompileFileSizeLimitBlocks),
		"bpfcompat-sandbox",
		strconv.Itoa(sourceCompileCPULimitSeconds(cpuLimit)),
	)
	return append(args, command...)
}

func sourceCompileCPULimitSeconds(timeout time.Duration) int {
	seconds := int((timeout + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return seconds + 1
}

// runSourceCompileSandboxed runs command inside the sandbox and returns its
// combined output. On ctx expiry the bwrap process group is SIGKILLed; the
// sandboxed tree dies with it (--die-with-parent, and it lives in its own
// PID namespace whose init is killed).
func runSourceCompileSandboxed(ctx context.Context, bwrap, workDir string, cpuLimit time.Duration, command []string) ([]byte, error) {
	//nolint:gosec // G204: bwrap is resolved by the server, the argv is built here; only the sanitized clang args come from the request
	cmd := exec.CommandContext(ctx, bwrap, sourceCompileSandboxArgs(workDir, cpuLimit, command)...)
	// bwrap needs nothing from the server environment; --clearenv already
	// empties the sandbox side.
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = sourceCompileSandboxKillGrace
	return cmd.CombinedOutput()
}
