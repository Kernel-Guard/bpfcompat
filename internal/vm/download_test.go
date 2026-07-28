package vm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureImageChecksumRehashesCachedImage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.qcow2")
	if err := os.WriteFile(path, []byte("image-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := ensureImageChecksum(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("image-v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := ensureImageChecksum(path)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("expected digest to change after cached image bytes changed")
	}
}

func TestDownloadFileWithLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("12345"))
	}))
	t.Cleanup(server.Close)

	out := filepath.Join(t.TempDir(), "image")
	client := &http.Client{Timeout: time.Second}
	err := downloadFileWithLimit(context.Background(), client, server.URL, out, 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("partial output should be removed, stat error=%v", statErr)
	}
}

func TestDownloadFileWithLimitCreatesPrivateFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("image"))
	}))
	t.Cleanup(server.Close)

	out := filepath.Join(t.TempDir(), "image")
	err := downloadFileWithLimit(context.Background(), &http.Client{Timeout: time.Second}, server.URL, out, 1024)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected downloaded image mode 0600, got %o", info.Mode().Perm())
	}
}

func TestDownloadFileWithLimitRejectsChunkedOverflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("12345"))
	}))
	t.Cleanup(server.Close)

	out := filepath.Join(t.TempDir(), "image")
	err := downloadFileWithLimit(context.Background(), &http.Client{Timeout: time.Second}, server.URL, out, 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("expected streamed size-limit error, got %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("partial streamed output should be removed, stat error=%v", statErr)
	}
}

func TestDownloadFileWithLimitHonorsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("image"))
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	out := filepath.Join(t.TempDir(), "image")
	err := downloadFileWithLimit(ctx, &http.Client{Timeout: time.Second}, server.URL, out, 1024)
	if err == nil {
		t.Fatal("expected canceled download")
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("canceled output should be removed, stat error=%v", statErr)
	}
}
