package api

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestSourceCompileDoesNotLeakServerEnvironmentToClang pins that the clang
// child process gets a minimal allowlisted environment. Anything clang can
// read it can also embed into the object (e.g. .incbin "/proc/self/environ")
// and surface through report notes, so server secrets must never reach it.
func TestSourceCompileDoesNotLeakServerEnvironmentToClang(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fake clang reads /proc/<pid>/environ")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}

	stubDir := t.TempDir()
	dumpPath := filepath.Join(t.TempDir(), "clang-environ")
	// /proc/$$/environ is the environment exactly as exec'd, before the
	// shell adds PWD/SHLVL/_; the dump path is baked in so the stub needs
	// no inherited variables.
	stub := "#!/bin/sh\n/bin/cat /proc/$$/environ > '" + dumpPath + "'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(stubDir, "clang"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	// The stub lives outside the sandbox's view; pin the bare-host path,
	// where the environment allowlist is the only protection.
	forceUnsandboxedSourceCompile(t)

	t.Setenv(envAllowAnonymousValidate, "")
	t.Setenv(envAllowAnonymousWrite, "")
	t.Setenv(envWriteAPIKey, testDisclosureWriteKey)
	t.Setenv("BPFCOMPAT_GITHUB_MARKETPLACE_WEBHOOK_SECRET", "env-canary-webhook-secret")
	t.Setenv("UNRELATED_SERVER_ENV_CANARY", "env-canary-unrelated")

	rec := postValidateSource(t, sourceUploadAsText, "int x;\n", true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 from failing fake clang, got %d body=%s", rec.Code, rec.Body.String())
	}

	raw, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("fake clang did not run: %v", err)
	}
	allowed := map[string]bool{
		"PATH": true, "TMPDIR": true, "CPATH": true, "C_INCLUDE_PATH": true,
		"LANG": true, "LC_ALL": true,
	}
	got := map[string]string{}
	var unexpected []string
	for _, kv := range strings.Split(string(raw), "\x00") {
		if kv == "" {
			continue
		}
		name, value, _ := strings.Cut(kv, "=")
		got[name] = value
		if !allowed[name] {
			unexpected = append(unexpected, name)
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Fatalf("clang inherited non-allowlisted environment variables: %v", unexpected)
	}
	if !strings.Contains(got["PATH"], stubDir) {
		t.Fatalf("clang must still receive PATH, got %q", got["PATH"])
	}
	if strings.Contains(string(raw), "env-canary") || strings.Contains(string(raw), testDisclosureWriteKey) {
		t.Fatalf("server secret values reached clang environment")
	}
}
