package api

// Regression tests for the residual A1-1 disclosure: even with diagnostics
// hidden, an authenticated (or opted-in anonymous) caller could compile a
// source that pulls host files into the object itself (.incbin, #include,
// __has_include probes, /proc/self/environ). Bytes of that object can come
// back to the client through verifier-rejection notes, so clang must not be
// able to see any host file outside the request directory and the system
// toolchain. These tests use only fake secrets created in t.TempDir() and
// deliberately reference no symbols added by the sandbox change, so the file
// also compiles (and fails) against the pre-sandbox tree.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const sandboxIsolationSecretToken = "SANDBOX_FAKE_HOST_SECRET_7d1e93"

// requireRunnableBwrap skips the test unless bubblewrap can actually build
// the namespaces the compile sandbox needs on this machine (on Ubuntu 24.04+
// kernel.apparmor_restrict_unprivileged_userns=1 blocks it unless an
// AppArmor profile grants bwrap the userns permission).
func requireRunnableBwrap(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap (bubblewrap) not installed; compile sandbox cannot run here")
	}
	args := []string{"--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/usr", "/usr"}
	for _, name := range []string{"bin", "lib", "lib64"} {
		if target, err := os.Readlink("/" + name); err == nil {
			args = append(args, "--symlink", target, "/"+name)
		} else if st, err := os.Stat("/" + name); err == nil && st.IsDir() {
			args = append(args, "--ro-bind", "/"+name, "/"+name)
		}
	}
	args = append(args, "--", "/bin/sh", "-c", "exit 0")
	if out, err := exec.Command(bwrap, args...).CombinedOutput(); err != nil {
		t.Skipf("bwrap is installed but not runnable here (%v: %s); on Ubuntu this is usually kernel.apparmor_restrict_unprivileged_userns=1 without a bwrap AppArmor profile", err, strings.TrimSpace(string(out)))
	}
}

func TestSourceCompileSandboxBlocksHostFileReads(t *testing.T) {
	requireRunnableBwrap(t)
	// Make sure no opt-out from a developer shell weakens the run.
	t.Setenv("BPFCOMPAT_API_UNSANDBOXED_SOURCE_COMPILE", "")

	secretDir := t.TempDir()
	rawSecret := filepath.Join(secretDir, "server-secret.env")
	if err := os.WriteFile(rawSecret, []byte("BPFCOMPAT_API_WRITE_KEY="+sandboxIsolationSecretToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Valid C so an #include of it would compile cleanly on an unsandboxed
	// host and land the token in .rodata.
	cSecret := filepath.Join(secretDir, "secret.h")
	if err := os.WriteFile(cSecret, []byte("const char leaked_secret[] = \""+sandboxIsolationSecretToken+"\";\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	incbin := func(path string) string {
		return "__asm__(\".section .rodata\\n.incbin \\\"" + path + "\\\"\\n\");\n"
	}
	hasIncludeMarker := func(path string) string {
		return "#if __has_include(\"" + path + "\")\nconst char saw_host_file[] = \"" + sandboxIsolationSecretToken + "\";\n#endif\nint ok;\n"
	}

	cases := []struct {
		name        string
		source      string
		forbidden   []string
		mustCompile bool
	}{
		// Positive control: a harmless source must still compile, so the
		// cases below cannot pass just because compilation is broken.
		{name: "control compiles", source: "const char ctl[] = \"control\";\n", mustCompile: true},
		{name: "incbin absolute secret", source: incbin(rawSecret), forbidden: []string{sandboxIsolationSecretToken}},
		{name: "quoted include absolute secret", source: "#include \"" + cSecret + "\"\n", forbidden: []string{sandboxIsolationSecretToken}},
		{name: "angle include absolute secret", source: "#include <" + cSecret + ">\n", forbidden: []string{sandboxIsolationSecretToken}},
		{name: "has_include probe of secret", source: hasIncludeMarker(rawSecret), forbidden: []string{sandboxIsolationSecretToken}},
		{name: "has_include probe of etc hostname", source: "#if __has_include(</etc/hostname>) || __has_include(</etc/passwd>)\nconst char saw_etc[] = \"" + sandboxIsolationSecretToken + "\";\n#endif\nint ok;\n", forbidden: []string{sandboxIsolationSecretToken}},
		{name: "incbin etc passwd", source: incbin("/etc/passwd"), forbidden: []string{"root:"}},
		// procfs files stat as size 0, so .incbin of them embeds nothing even
		// unsandboxed; kept to pin that no host /proc is reachable.
		{name: "incbin proc self environ", source: incbin("/proc/self/environ"), forbidden: []string{"PATH="}},
		{name: "include sibling upload via relative path", source: "#include \"../neighbour/secret.h\"\n", forbidden: []string{sandboxIsolationSecretToken}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uploads := t.TempDir()
			requestDir := filepath.Join(uploads, "request")
			neighbour := filepath.Join(uploads, "neighbour")
			for _, dir := range []string{requestDir, neighbour} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// Another request's upload, one directory up from this one
			// (a quoted #include resolves relative to the including file).
			if err := os.WriteFile(filepath.Join(neighbour, "secret.h"), []byte("const char neighbour_secret[] = \""+sandboxIsolationSecretToken+"\";\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			sourcePath := filepath.Join(requestDir, "uploaded-source.bpf.c")
			if err := os.WriteFile(sourcePath, []byte(tc.source), 0o644); err != nil {
				t.Fatal(err)
			}

			outPath, err := compileSourceFile(context.Background(), sourcePath, requestDir, "", nil)
			if err != nil && tc.mustCompile {
				t.Fatalf("control source failed to compile: %v", err)
			}
			if err != nil {
				// Refusing to compile is fine: the path is absent inside the
				// sandbox. The error must not echo the secret either.
				for _, forbidden := range tc.forbidden {
					if strings.Contains(err.Error(), forbidden) {
						t.Fatalf("compile error disclosed %q: %v", forbidden, err)
					}
				}
				return
			}
			obj, readErr := os.ReadFile(outPath)
			if readErr != nil {
				t.Fatalf("compile reported success but object is unreadable: %v", readErr)
			}
			for _, forbidden := range tc.forbidden {
				if bytes.Contains(obj, []byte(forbidden)) {
					t.Fatalf("compiled object embeds host data %q read outside the request dir", forbidden)
				}
			}
		})
	}
}
