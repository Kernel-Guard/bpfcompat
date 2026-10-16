package main

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/runner"
)

func TestApplyTargetTimeoutFlag(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantTO     time.Duration
		wantMatrix bool
		wantErr    bool
	}{
		// No --timeout: the 180s default is a fallback and matrix
		// `timeout:` fields apply (kernel-sweep matrices say 20m).
		{name: "flag omitted", args: nil, wantTO: 180 * time.Second, wantMatrix: true},
		// Explicit --timeout always wins, so CI lanes passing --timeout 12m
		// keep a 12m per-target budget even on a `timeout: 20m` matrix.
		{name: "explicit", args: []string{"--timeout", "12m"}, wantTO: 12 * time.Minute},
		{name: "explicit equal to default", args: []string{"--timeout=180s"}, wantTO: 180 * time.Second},
		{name: "garbage", args: []string{"--timeout", "banana"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			text := fs.String("timeout", "180s", "")
			if err := fs.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			var cfg runner.Config
			err := applyTargetTimeoutFlag(fs, *text, &cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Timeout != tt.wantTO || cfg.MatrixProfileTimeouts != tt.wantMatrix {
				t.Fatalf("got Timeout=%v MatrixProfileTimeouts=%v, want %v %v",
					cfg.Timeout, cfg.MatrixProfileTimeouts, tt.wantTO, tt.wantMatrix)
			}
		})
	}
}

func TestKernelSweepRejectsInvalidTargetTimeout(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	code := runKernelSweep([]string{
		"--profile", "ubuntu-22.04-5.15",
		"--profile-dir", "../../vm/profiles",
		"--crawler-file", "/nonexistent/list.json",
		"--target-timeout", "banana",
	})
	os.Stderr = orig
	_ = w.Close()
	out, _ := io.ReadAll(r)
	if code != runner.ExitToolError {
		t.Fatalf("exit = %d, want %d", code, runner.ExitToolError)
	}
	if !strings.Contains(string(out), "--target-timeout") {
		t.Fatalf("stderr does not reject --target-timeout: %q", out)
	}
}
