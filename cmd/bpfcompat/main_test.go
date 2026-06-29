package main

import (
	"reflect"
	"testing"
)

func TestStripHiddenUnsafeHostRunnerFlag(t *testing.T) {
	args := []string{
		"--artifact", "a.o",
		"--unsafe-allow-host-runner=true",
		"--matrix", "m.yaml",
	}

	filtered, allow, err := stripHiddenUnsafeHostRunnerFlag(args)
	if err != nil {
		t.Fatalf("strip hidden flag: %v", err)
	}
	if !allow {
		t.Fatalf("expected hidden allow flag to be true")
	}

	want := []string{"--artifact", "a.o", "--matrix", "m.yaml"}
	if !reflect.DeepEqual(filtered, want) {
		t.Fatalf("unexpected filtered args: got=%v want=%v", filtered, want)
	}
}

func TestStripHiddenUnsafeHostRunnerFlagInvalidBool(t *testing.T) {
	_, _, err := stripHiddenUnsafeHostRunnerFlag([]string{"--unsafe-allow-host-runner=maybe"})
	if err == nil {
		t.Fatalf("expected parse error for invalid hidden bool")
	}
}

func TestSplitCSVUpper(t *testing.T) {
	got := splitCSVUpper("unknown, missing_btf, ,Unsupported_Map_Type")
	want := []string{"UNKNOWN", "MISSING_BTF", "UNSUPPORTED_MAP_TYPE"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected splitCSVUpper result: got=%v want=%v", got, want)
	}
}

func TestRunTestCommandValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"missing cmd", []string{"--matrix", "m.yaml", "--out", "o.json"}, 1},
		{"help", []string{"-h"}, 0},
		{"unexpected positional", []string{"--cmd", "x", "--matrix", "m.yaml", "--out", "o.json", "stray"}, 1},
		{"bad timeout", []string{"--cmd", "x", "--matrix", "m.yaml", "--out", "o.json", "--timeout", "nope"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runTestCommand(tc.args); got != tc.want {
				t.Fatalf("runTestCommand(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}

// test-command must route through the same command-mode config as `test --command`.
func TestRunTestCommandDispatch(t *testing.T) {
	if got := run([]string{"test-command", "-h"}); got != 0 {
		t.Fatalf("run test-command -h = %d, want 0", got)
	}
}
