//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

const envServeSignalChild = "BPFCOMPAT_TEST_SERVE_SIGNAL_CHILD_ADDR"

// TestServeSignalChild is the child half of TestServeExitsCleanlyOnSIGTERM:
// it only runs when re-executed with envServeSignalChild set.
func TestServeSignalChild(t *testing.T) {
	addr := os.Getenv(envServeSignalChild)
	if addr == "" {
		t.Skip("helper process for TestServeExitsCleanlyOnSIGTERM")
	}
	os.Exit(runServe([]string{"--addr", addr, "--workdir", t.TempDir()}))
}

// A4-1: SIGTERM to `bpfcompat serve` must run the graceful drain and exit 0
// instead of the default signal death (exit 143 / killed by SIGTERM).
func TestServeExitsCleanlyOnSIGTERM(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServeSignalChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), envServeSignalChild+"="+addr, "BPFCOMPAT_API_SHUTDOWN_DRAIN_TIMEOUT=1s")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve child: %v", err)
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/livez", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal("serve child never became ready")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	err = cmd.Wait()
	if err == nil {
		return
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			t.Fatalf("serve was killed by %v instead of shutting down gracefully", ws.Signal())
		}
		t.Fatalf("serve exited with code %d after SIGTERM, want 0", exitErr.ExitCode())
	}
	t.Fatalf("wait for serve child: %v", err)
}
