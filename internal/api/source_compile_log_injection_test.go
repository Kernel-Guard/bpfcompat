package api

// Regression test for CodeQL go/log-injection alert #179 (CWE-117): the
// source-compile failure log carries the uploaded source path, which derives
// from the client-chosen multipart filename. Line breaks in it must never
// reach the log sink verbatim, or a client could forge extra log lines.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceCompileFailureLogStripsLineBreaksFromSourcePath(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}
	// Bare-host compile keeps the test independent of whether bwrap can run
	// here; the log line under test is the same on both paths.
	forceUnsandboxedSourceCompile(t)
	dir := t.TempDir()
	// Linux allows CR/LF in file names, so this is a real on-disk path that
	// clang can open and fail on.
	forgedName := "evil\nlevel=ERROR msg=forged\r.bpf.c"
	sourcePath := filepath.Join(dir, forgedName)
	if err := os.WriteFile(sourcePath, []byte("this_is_not_c;\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	if _, err := compileSourceFile(context.Background(), sourcePath, dir, "", logger); err == nil {
		t.Fatal("expected compile failure for invalid source")
	}
	assertSourceLogAttrHasNoLineBreaks(t, buf.String(), "source upload compile failed")
}

func TestSourceCompileUnusableObjectLogStripsLineBreaksFromSourcePath(t *testing.T) {
	forceUnsandboxedSourceCompile(t)
	// A stand-in clang that "succeeds" without writing the object drives
	// compileSourceFile into the non-regular-object branch deterministically.
	binDir := t.TempDir()
	fakeClang := filepath.Join(binDir, "clang")
	if err := os.WriteFile(fakeClang, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	dir := t.TempDir()
	forgedName := "evil\nlevel=ERROR msg=forged\r.bpf.c"
	sourcePath := filepath.Join(dir, forgedName)
	if err := os.WriteFile(sourcePath, []byte("int x;\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	if _, err := compileSourceFile(context.Background(), sourcePath, dir, "", logger); err == nil {
		t.Fatal("expected an error when the compiler leaves no object behind")
	}
	assertSourceLogAttrHasNoLineBreaks(t, buf.String(), "source upload compile produced an unusable object")
}

func assertSourceLogAttrHasNoLineBreaks(t *testing.T, logs, msg string) {
	t.Helper()
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		if rec["msg"] != msg {
			continue
		}
		found = true
		source, _ := rec["source"].(string)
		if source == "" {
			t.Fatalf("expected a source attribute, got %v", rec)
		}
		if strings.ContainsAny(source, "\r\n") {
			t.Fatalf("source attribute must not carry raw line breaks, got %q", source)
		}
	}
	if !found {
		t.Fatalf("expected a %q log record, got %s", msg, logs)
	}
}
