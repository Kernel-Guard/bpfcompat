package api

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// forceUnsandboxedSourceCompile makes the sandbox probe fail (missing bwrap)
// and sets the operator opt-out, so the test exercises bare-host clang.
func forceUnsandboxedSourceCompile(t *testing.T) {
	t.Helper()
	simulateMissingSandbox(t)
	t.Setenv(envUnsandboxedSourceCompile, "true")
}

func simulateMissingSandbox(t *testing.T) {
	t.Helper()
	prev := sourceCompileBwrapBinary
	sourceCompileBwrapBinary = filepath.Join(t.TempDir(), "no-such-bwrap")
	resetSourceCompileSandboxProbe()
	t.Cleanup(func() {
		sourceCompileBwrapBinary = prev
		resetSourceCompileSandboxProbe()
	})
}

func useRealSandbox(t *testing.T) {
	t.Helper()
	requireRunnableBwrap(t)
	t.Setenv(envUnsandboxedSourceCompile, "")
	resetSourceCompileSandboxProbe()
	t.Cleanup(resetSourceCompileSandboxProbe)
}

func TestSourceCompileSandboxArgsExposeOnlyToolchainAndWorkDir(t *testing.T) {
	t.Setenv("CPATH", "/opt/bpf-headers:/usr/include/extra:relative:/")
	t.Setenv("C_INCLUDE_PATH", "")
	args := sourceCompileSandboxArgs("/srv/state/uploads/abc", 30*time.Second, []string{"/usr/bin/clang", "--version"})
	joined := strings.Join(args, " ")
	for _, want := range []string{"--unshare-all", "--die-with-parent", "--new-session", "--clearenv", "--cap-drop ALL",
		"--ro-bind /usr /usr", "--dev /dev", "--tmpfs /tmp", "--bind /srv/state/uploads/abc /work", "--chdir /work",
		"--ro-bind-try /opt/bpf-headers /opt/bpf-headers"} {
		if !strings.Contains(joined, want) {
			t.Errorf("sandbox argv missing %q: %s", want, joined)
		}
	}
	sep := slices.Index(args, "--")
	if sep < 0 {
		t.Fatalf("sandbox argv has no -- separator: %s", joined)
	}
	opts := args[:sep]
	for i, arg := range opts {
		if arg != "--bind" && arg != "--ro-bind" && arg != "--ro-bind-try" && arg != "--bind-try" {
			continue
		}
		src := opts[i+1]
		switch {
		case arg == "--bind" && src == "/srv/state/uploads/abc":
		case src == "/usr" || src == "/etc/ld.so.cache" || src == "/opt/bpf-headers":
		case slices.Contains([]string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}, src):
		default:
			t.Errorf("unexpected host path exposed to the compile sandbox: %s %s", arg, src)
		}
	}
	for _, forbidden := range []string{"--proc", "--share-net", "relative"} {
		if slices.Contains(opts, forbidden) {
			t.Errorf("sandbox argv must not contain %q: %s", forbidden, joined)
		}
	}
	if !slices.Equal(args[len(args)-2:], []string{"/usr/bin/clang", "--version"}) {
		t.Fatalf("command must be the argv tail, got %v", args[sep:])
	}
}

func TestSourceCompileFailsClosedWithoutSandbox(t *testing.T) {
	simulateMissingSandbox(t)
	t.Setenv(envUnsandboxedSourceCompile, "")

	requestDir := t.TempDir()
	sourcePath := filepath.Join(requestDir, "uploaded-source.bpf.c")
	if err := os.WriteFile(sourcePath, []byte("int x;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := compileSourceFile(context.Background(), sourcePath, requestDir, "", nil); !errors.Is(err, errSourceCompileSandboxUnavailable) {
		t.Fatalf("expected fail-closed sandbox error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(requestDir, "compiled.bpf.o")); !os.IsNotExist(err) {
		t.Fatalf("nothing may be compiled without a sandbox, stat err=%v", err)
	}

	t.Setenv(envAllowAnonymousValidate, "")
	t.Setenv(envAllowAnonymousWrite, "")
	t.Setenv(envWriteAPIKey, testDisclosureWriteKey)
	rec := postValidateSource(t, sourceUploadAsText, "int x;\n", true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no sandbox is available, got %d body=%s", rec.Code, rec.Body.String())
	}
	if msg := decodeAPIError(t, rec); !strings.Contains(msg, "sandbox") || !strings.Contains(msg, ".bpf.o") {
		t.Fatalf("expected clear sandbox-unavailable error, got %q", msg)
	}
}

func TestSourceCompileUnsandboxedOptInCompiles(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}
	forceUnsandboxedSourceCompile(t)

	requestDir := t.TempDir()
	sourcePath := filepath.Join(requestDir, "uploaded-source.bpf.c")
	if err := os.WriteFile(sourcePath, []byte("int x;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := compileSourceFile(context.Background(), sourcePath, requestDir, "", nil)
	if err != nil {
		t.Fatalf("explicit unsandboxed opt-in must still compile: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("compiled object missing: %v", err)
	}
}

// allocSections returns the loadable sections (program code, maps, license,
// rodata) of an object; debug info legitimately differs because the sandbox
// compiles under /work.
func allocSections(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]byte{}
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC == 0 || s.Type == elf.SHT_NOBITS {
			continue
		}
		data, err := s.Data()
		if err != nil {
			t.Fatal(err)
		}
		out[s.Name] = data
	}
	return out
}

func TestSourceCompileSandboxCompilesStandardBPFSource(t *testing.T) {
	useRealSandbox(t)
	if _, err := os.Stat("/usr/include/bpf/bpf_helpers.h"); err != nil {
		t.Skip("libbpf headers (bpf/bpf_helpers.h) not installed")
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "examples", "functional-execve", "functional_execve.bpf.c"))
	if err != nil {
		t.Fatal(err)
	}
	requestDir := t.TempDir()
	sourcePath := filepath.Join(requestDir, "uploaded-source.bpf.c")
	if err := os.WriteFile(sourcePath, src, 0o644); err != nil {
		t.Fatal(err)
	}
	sandboxed, err := compileSourceFile(context.Background(), sourcePath, requestDir, "", nil)
	if err != nil {
		t.Fatalf("standard BPF source must compile in the sandbox: %v", err)
	}

	hostDir := t.TempDir()
	hostOut := filepath.Join(hostDir, "host.bpf.o")
	cmd := exec.Command("clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-I/usr/include/x86_64-linux-gnu", "-c", sourcePath, "-o", hostOut)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("host clang failed: %v %s", err, out)
	}

	got, want := allocSections(t, sandboxed), allocSections(t, hostOut)
	if len(want) == 0 || len(got) != len(want) {
		t.Fatalf("loadable sections differ: sandbox=%d host=%d", len(got), len(want))
	}
	for name, data := range want {
		if !bytes.Equal(got[name], data) {
			t.Fatalf("section %s differs between sandboxed and host compile", name)
		}
	}
	if _, ok := got["tracepoint/syscalls/sys_enter_execve"]; !ok {
		t.Fatalf("program section missing from sandboxed object: %v", slices.Sorted(maps.Keys(got)))
	}
}

func TestSourceCompileSandboxEnvironmentAndLimits(t *testing.T) {
	useRealSandbox(t)
	t.Setenv("UNRELATED_SERVER_ENV_CANARY", "env-canary-value")
	script := `ulimit -t; ulimit -v; ulimit -f; ulimit -c; ` +
		`for p in /home /root /var /run /proc /sys /srv /opt /mnt /boot; do [ -e "$p" ] && echo "VISIBLE $p"; done; ` +
		`echo "ETC: $(ls -A /etc)"; /usr/bin/env`
	out, err := runSourceCompileSandboxed(context.Background(), mustLookPath(t, "bwrap"), t.TempDir(), 30*time.Second,
		[]string{"/bin/sh", "-c", script})
	if err != nil {
		t.Fatalf("sandboxed shell failed: %v %s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 4 || lines[0] != "31" || lines[1] != "2097152" || lines[2] != "131072" || lines[3] != "0" {
		t.Fatalf("expected cpu=31s as=2097152KiB fsize=131072 core=0 limits, got:\n%s", out)
	}
	if strings.Contains(string(out), "VISIBLE ") {
		t.Fatalf("host paths visible inside the compile sandbox:\n%s", out)
	}
	if !strings.Contains(string(out), "ETC: ld.so.cache\n") && !strings.Contains(string(out), "ETC: \n") {
		t.Fatalf("/etc in the sandbox must hold at most ld.so.cache:\n%s", out)
	}
	if strings.Contains(string(out), "env-canary") {
		t.Fatalf("server environment leaked into the sandbox:\n%s", out)
	}
}

func TestSourceCompileSandboxTimeoutKillsProcessTree(t *testing.T) {
	useRealSandbox(t)
	const marker = "4242.4242"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err := runSourceCompileSandboxed(ctx, mustLookPath(t, "bwrap"), t.TempDir(), 30*time.Second,
		[]string{"/bin/sh", "-c", "/usr/bin/sleep " + marker + " & /usr/bin/sleep " + marker + "; wait"})
	if err == nil {
		t.Fatal("expected the sandboxed command to be killed")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("timeout took %s to stop the sandbox", elapsed)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		survivors := processesWithArg(t, marker)
		if len(survivors) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandboxed processes survived the timeout: %v", survivors)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestSourceCompileSandboxReportsUploadedSourceLocations(t *testing.T) {
	useRealSandbox(t)
	requestDir := t.TempDir()
	sourcePath := filepath.Join(requestDir, "uploaded-source.bpf.c")
	if err := os.WriteFile(sourcePath, []byte("int ok;\n\nthis_is_not_c secret_identifier_xyz;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := compileSourceFile(context.Background(), sourcePath, requestDir, "", nil)
	if err == nil || !strings.HasPrefix(err.Error(), "source compilation failed at uploaded source line 3:") {
		t.Fatalf("sandboxed compile errors must keep uploaded-source locations, got %v", err)
	}
	if strings.Contains(err.Error(), "secret_identifier_xyz") || strings.Contains(err.Error(), "/work") {
		t.Fatalf("compile error must not echo source text or sandbox paths, got %q", err)
	}
}

func mustLookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not available", name)
	}
	return p
}

func processesWithArg(t *testing.T, arg string) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Skipf("cannot scan /proc: %v", err)
	}
	var found []string
	for _, e := range entries {
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if slices.Contains(strings.Split(string(cmdline), "\x00"), arg) {
			found = append(found, e.Name()+":"+strings.ReplaceAll(string(cmdline), "\x00", " "))
		}
	}
	return found
}
