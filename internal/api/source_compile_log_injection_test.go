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

	var found bool
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		if rec["msg"] != "source upload compile failed" {
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
		t.Fatalf("expected a compile-failure log record, got %s", buf.String())
	}
}
