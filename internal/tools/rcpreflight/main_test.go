package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestActiveWorkflowPins(t *testing.T) {
	sha := strings.Repeat("a", 40)
	tag := "v0.4.0-rc.5"
	good := "Kernel-Guard/bpfcompat@" + sha + " # " + tag
	workflow := func(steps string) string { return "jobs:\n  test:\n    steps:\n" + steps }
	tests := []struct {
		name, mode, text string
		ok               bool
	}{
		{"plain", "all", workflow("      - uses: " + good + "\n"), true},
		{"quoted", "all", workflow("      - uses: 'kernel-guard/bpfcompat@" + sha + "' # " + tag + "\n"), true},
		{"marker", "candidate", workflow("      - name: candidate\n        # bpfcompat-pin: candidate\n        uses: " + good + "\n"), true},
		{"comment-only", "all", workflow("      # - uses: " + good + "\n      - run: true\n"), false},
		{"hidden-ref", "all", workflow("      - uses: " + good + "\n      - uses: Kernel-Guard/bpfcompat@main\n"), false},
		{"folded-ref", "all", workflow("      - uses: " + good + "\n      - uses: >-\n          Kernel-Guard/bpfcompat@main\n"), false},
		{"unicode-ref", "all", workflow("      - uses: " + good + "\n      - uses: \"Kernel-\\u0047uard/bpfcompat@main\"\n"), false},
		{"run-text", "all", workflow("      - run: |\n          uses: " + good + "\n"), false},
		{"run-marker", "candidate", workflow("      - run: |\n          # bpfcompat-pin: candidate\n          uses: " + good + "\n      - uses: Kernel-Guard/bpfcompat@main\n"), false},
		{"flow-stale", "all", workflow("      - uses: " + good + "\n      - {uses: 'Kernel-Guard/bpfcompat@main'}\n"), false},
		{"flow-correct", "all", "jobs: {test: {steps: [{uses: 'Kernel-Guard/bpfcompat@" + sha + "'}]}}\n", false}, // missing tag comment
		{"quoted-key", "all", workflow("      - uses: " + good + "\n      - 'uses': Kernel-Guard/bpfcompat@main\n"), false},
		{"wrong-tag", "all", workflow("      - uses: Kernel-Guard/bpfcompat@" + sha + " # v0.4.0-rc.4\n"), false},
		{"duplicate-key", "all", workflow("      - uses: " + good + "\n        uses: Kernel-Guard/bpfcompat@main\n"), false},
		{"duplicate-marker", "candidate", workflow("      - name: first\n        # bpfcompat-pin: candidate\n        uses: " + good + "\n      - name: second\n        # bpfcompat-pin: candidate\n        uses: " + good + "\n"), false},
		{"alias", "all", workflow("      - uses: &pin Kernel-Guard/bpfcompat@" + sha + " # " + tag + "\n      - uses: *pin\n"), false},
		{"multi-document", "all", workflow("      - uses: "+good+"\n") + "---\njobs: {}\n", false},
		{"no-jobs", "all", "run: 'uses: " + good + "'\n", false},
		{"wrong-type", "all", workflow("      - uses: [invalid]\n"), false},
		{"subpath", "all", workflow("      - uses: " + good + "\n      - uses: Kernel-Guard/bpfcompat/sub@" + sha + " # " + tag + "\n"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := check(strings.NewReader(tt.text), tt.mode, sha, tag)
			if (err == nil) != tt.ok {
				t.Fatalf("check() = %v, want accepted=%v", err, tt.ok)
			}
		})
	}
}

func TestRunExitCodes(t *testing.T) {
	sha := strings.Repeat("a", 40)
	tag := "v0.4.0-rc.5"
	dir := t.TempDir()
	good := dir + "/good.yml"
	stale := dir + "/stale.yml"
	if err := os.WriteFile(good, []byte("jobs:\n  t:\n    steps:\n      - uses: Kernel-Guard/bpfcompat@"+sha+" # "+tag+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("jobs:\n  t:\n    steps:\n      - uses: Kernel-Guard/bpfcompat@main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"verified", []string{"all", sha, tag, good}, 0, "VERIFIED\n"},
		{"pending", []string{"all", sha, tag, stale}, 0, "PENDING\n"},
		{"usage", []string{"all", sha, tag}, 2, ""},
		{"unknown-mode", []string{"some", sha, tag, good}, 2, ""},
		{"unreadable", []string{"all", sha, tag, dir + "/missing.yml"}, 2, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != tt.code || stdout.String() != tt.out {
				t.Fatalf("run() = %d, %q; want %d, %q (stderr %q)", code, stdout.String(), tt.code, tt.out, stderr.String())
			}
		})
	}
}
